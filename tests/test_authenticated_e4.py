# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Real FreeTSA tokens, no network; test-only custodian receipts.

Only public TSA certificates are checked in. Retention signing keys are fresh
in-memory test data and are never persisted. E4 here demonstrates verification
under an explicitly trusted TEST custodian, not a real storage service claim.
"""
import base64
import hashlib
import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from pathlib import Path

import nacl.signing
import pytest
from asn1crypto import tsp

from witnessos_verifier.timestamp import verify_timestamp
from witnessos_verifier.trust_policy import TrustPolicy, TrustLevel
from witnessos_verifier.verifier import verify
from witnessos_verifier.worm import canonical_json, snapshot_inventory
from tests.test_adversarial_bundle import rehash_worm

TSA = 'https://freetsa.org/tsr'
CERTS = Path(__file__).parent / 'public_tsa_certificates'


@pytest.fixture
def tsa_policy():
    return TrustPolicy(level=TrustLevel.STANDARD, allowed_tsa_urls={TSA},
                       trusted_roots=[CERTS/'freetsa-root.pem'],
                       untrusted_certificates=[CERTS/'freetsa-tsa.pem'])


def imprint(p):
    return hashlib.sha256(bytes.fromhex(json.loads((p/'batch_manifest.json').read_text())['root'])).digest()


@pytest.mark.parametrize('name', ['e4-gmail-approved-send', 'e4-stripe-refund'])
def test_real_freetsa_signatures(bundle_path, tsa_policy, name):
    p = bundle_path.parent/name
    r = verify_timestamp(p/'timestamp/batch_timestamp.tsr', imprint(p), tsa_policy, TSA)
    assert r.valid, r.errors
    assert r.signature_verified and r.trust_verified
    assert r.imprint_matches


@pytest.mark.parametrize('change', ['signature', 'imprint', 'attributes', 'trailing', 'truncated', 'empty_signers'])
def test_bad_token_rejected(bundle_path, tsa_policy, tmp_path, change):
    raw = (bundle_path/'timestamp/batch_timestamp.tsr').read_bytes()
    r = tsp.TimeStampResp.load(raw)
    sd = r['time_stamp_token']['content']
    if change == 'signature':
        sig = sd['signer_infos'][0]['signature'].native
        sd['signer_infos'][0]['signature'] = sig[:-1] + bytes([sig[-1] ^ 1])
        raw = r.dump()
    elif change == 'attributes':
        attrs = sd['signer_infos'][0]['signed_attrs']
        for attr in attrs:
            if attr['type'].native == 'message_digest':
                attr['values'] = [b'\0' * len(attr['values'][0].native)]
        raw = r.dump()
    elif change == 'trailing':
        raw += b'garbage'
    elif change == 'truncated':
        raw = raw[:-5]
    elif change == 'empty_signers':
        sd['signer_infos'] = []
        raw = r.dump()
    token = tmp_path/'bad.tsr'; token.write_bytes(raw)
    expected = b'\0'*32 if change == 'imprint' else imprint(bundle_path)
    checked = verify_timestamp(token, expected, tsa_policy, TSA)
    assert not checked.valid and not checked.signature_verified
    assert checked.errors


@pytest.mark.parametrize('policy_change', ['no_roots', 'wrong_root', 'missing_signer', 'demo', 'strict',
                                          'window_before', 'window_after', 'age', 'nonce', 'signature_algorithm', 'tsa_url'])
def test_trust_policy_rejections(bundle_path, tsa_policy, policy_change):
    p = tsa_policy
    if policy_change == 'no_roots': p = replace(p, trusted_roots=[])
    elif policy_change == 'wrong_root': p = replace(p, trusted_roots=[CERTS/'freetsa-tsa.pem'])
    elif policy_change == 'missing_signer': p = replace(p, untrusted_certificates=[])
    elif policy_change == 'demo': p = TrustPolicy.demo()
    elif policy_change == 'strict': p = replace(p, level=TrustLevel.STRICT)
    elif policy_change == 'window_before': p = replace(p, timestamp_not_before=datetime(2027, 1, 1, tzinfo=timezone.utc))
    elif policy_change == 'window_after': p = replace(p, timestamp_not_after=datetime(2025, 1, 1, tzinfo=timezone.utc))
    elif policy_change == 'age': p = replace(p, max_timestamp_age_seconds=1)
    elif policy_change == 'nonce': p = replace(p, require_nonce_echo=True)
    elif policy_change == 'signature_algorithm': p = replace(p, allowed_signature_algorithms=set())
    elif policy_change == 'tsa_url': p = replace(p, allowed_tsa_urls={'https://other.example/tsa'})
    r = verify_timestamp(bundle_path/'timestamp/batch_timestamp.tsr', imprint(bundle_path), p, TSA)
    assert not r.valid and r.errors


def test_future_timestamp_rejected(bundle_path, tsa_policy):
    r = verify_timestamp(bundle_path/'timestamp/batch_timestamp.tsr', imprint(bundle_path), tsa_policy, TSA,
                         now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert not r.valid and 'future' in r.errors[0]


def test_actual_nonce(bundle_path, tsa_policy):
    p = bundle_path.parent/'e4-stripe-refund'
    policy = replace(tsa_policy, require_nonce_echo=True)
    good = verify_timestamp(p/'timestamp/batch_timestamp.tsr', imprint(p), policy, TSA, expected_nonce=0xDF53C2B513C42038)
    bad = verify_timestamp(p/'timestamp/batch_timestamp.tsr', imprint(p), policy, TSA, expected_nonce=1)
    assert good.valid, good.errors
    assert not bad.valid and 'nonce mismatch' in bad.errors[0]


def make_test_custody_receipt(p, sk):
    m = json.loads((p/'batch_manifest.json').read_text())
    now = datetime.now(timezone.utc)
    receipt = dict(schema='witnessos-retention-v1', authority='TEST-CUSTODIAN-NOT-PRODUCTION',
                   batch_id=m['batch_id'], case_id=m['case_id'], merkle_root=m['root'],
                   snapshot_sha256=hashlib.sha256(canonical_json(snapshot_inventory(p))).hexdigest(),
                   object_uri='test://custodian/snapshot', version_id='test-version-1',
                   retention_mode='COMPLIANCE', issued_at=now.isoformat(),
                   retain_until=(now+timedelta(days=365)).isoformat())
    receipt['signature'] = base64.b64encode(sk.sign(canonical_json(receipt)).signature).decode()
    (p/'worm/retention.json').write_text(json.dumps(receipt))


@pytest.fixture
def controlled_e4(bundle_path, tsa_policy, tmp_path):
    p = tmp_path/'controlled-e4'
    shutil.copytree(bundle_path, p)
    sk = nacl.signing.SigningKey.generate()  # ephemeral TEST custodian; no production keys
    make_test_custody_receipt(p, sk)
    # These tests are about an operator that REQUIRES authenticated retention, so
    # the policy demands it. The default, where retention is a recorded attribute
    # and never a grade requirement, is exercised by test_e4_json_cli_and_alpha
    # and by the attribute assertions in test_grade_integrity.
    policy = replace(tsa_policy, require_retention=True,
                     retention_authorities={'TEST-CUSTODIAN-NOT-PRODUCTION': bytes(sk.verify_key).hex()})
    return p, policy, sk


def test_real_crypto_e4_with_test_custodian(controlled_e4):
    p, policy, _ = controlled_e4
    r = verify(p, trust_policy=policy, tsa_url=TSA)
    assert r.valid and r.evidence_grade == 'E4', r.errors
    assert r.timestamp_result.signature_verified and r.timestamp_result.trust_verified
    assert r.worm_result.retention_verified


@pytest.mark.parametrize('attack', ['signature', 'authority', 'digest', 'expired', 'wrong_batch', 'mode', 'missing', 'rename', 'unknown_authority'])
def test_retention_attack(controlled_e4, attack):
    p, policy, sk = controlled_e4
    f = p/'worm/retention.json'; receipt = json.loads(f.read_text())
    if attack == 'missing': f.unlink()
    elif attack == 'rename': (p/'README.md').rename(p/'renamed.md')
    elif attack == 'unknown_authority': policy = replace(policy, retention_authorities={})
    else:
        if attack == 'signature': receipt['signature'] = 'AAAA'
        elif attack == 'authority': receipt['authority'] = 'untrusted'
        elif attack == 'digest': receipt['snapshot_sha256'] = '0'*64
        elif attack == 'expired': receipt['retain_until'] = '2020-01-01T00:00:00Z'
        elif attack == 'wrong_batch': receipt['batch_id'] = 'other'
        elif attack == 'mode': receipt['retention_mode'] = 'GOVERNANCE'
        # Even authentically signed but invalid claims must fail.
        if attack not in ('signature', 'authority'):
            del receipt['signature']
            receipt['signature'] = base64.b64encode(sk.sign(canonical_json(receipt)).signature).decode()
        f.write_text(json.dumps(receipt))
    rehash_worm(p)
    r = verify(p, trust_policy=policy, tsa_url=TSA)
    assert not r.valid and r.evidence_grade != 'E4'
    assert not r.worm_result.retention_verified


@pytest.mark.parametrize('attack', ['last_payload', 'last_signature', 'delete_proof', 'fake_proof',
                                   'timestamp_signature', 'truncate_events', 'malformed_manifest'])
def test_original_seven_with_real_trust(controlled_e4, attack):
    p, policy, _ = controlled_e4
    assert verify(p, trust_policy=policy, tsa_url=TSA).evidence_grade == 'E4'
    events = sorted((p/'events').glob('*.json'))
    if attack.startswith('last_'):
        d = json.loads(events[-1].read_text())
        if attack == 'last_payload': d['payload']['forged'] = True
        else: d['signed']['signature'] = 'AAAA'
        events[-1].write_text(json.dumps(d))
    elif attack == 'delete_proof': (p/'merkle_proof.json').unlink()
    elif attack == 'fake_proof': (p/'merkle_proof.json').write_text('{}')
    elif attack == 'timestamp_signature':
        f = p/'timestamp/batch_timestamp.tsr'; raw = bytearray(f.read_bytes()); raw[-1] ^= 1; f.write_bytes(raw)
    elif attack == 'truncate_events': events[-1].unlink()
    else: (p/'batch_manifest.json').write_text('{')
    rehash_worm(p)
    r = verify(p, trust_policy=policy, tsa_url=TSA)
    assert not r.valid and r.evidence_grade != 'E4'


def test_fixtures_have_real_tsa_and_retention_is_an_attribute(bundle_path, tsa_policy):
    """No retention receipt is an attribute, not a grade blocker (CUSTODY.md 7).

    The same bundles under a policy that DEMANDS custody must not reach E4. That
    second half is asserted here too, because it is what stops this rule from
    becoming a way to drop the requirement altogether.
    """
    for name in ('e4-gmail-approved-send', 'e4-stripe-refund'):
        bundle = bundle_path.parent/name
        r = verify(bundle, trust_policy=tsa_policy, tsa_url=TSA)
        assert r.timestamp_result.valid, r.errors
        assert r.evidence_grade == 'E4' and r.valid, (r.evidence_grade, r.errors)
        assert not r.worm_result.retention_verified
        assert any('Authenticated retention missing' in w for w in r.warnings)
        assert not any('Authenticated retention missing' in e for e in r.errors)

        demanding = replace(tsa_policy, require_retention=True)
        d = verify(bundle, trust_policy=demanding, tsa_url=TSA)
        assert d.evidence_grade == 'E3' and not d.valid
        assert any('Authenticated retention missing' in e for e in d.errors)


def test_embedded_tsa_certificate(bundle_path, tsa_policy, tmp_path):
    from asn1crypto import x509, pem
    token = tsp.TimeStampResp.load((bundle_path/'timestamp/batch_timestamp.tsr').read_bytes())
    _, _, der = pem.unarmor((CERTS/'freetsa-tsa.pem').read_bytes())
    token['time_stamp_token']['content']['certificates'] = [x509.Certificate.load(der)]
    p = tmp_path/'embedded.tsr'; p.write_bytes(token.dump())
    result = verify_timestamp(p, imprint(bundle_path), replace(tsa_policy, untrusted_certificates=[]), TSA)
    assert result.valid, result.errors


def test_missing_crypto_backend_is_failure(bundle_path, tsa_policy, monkeypatch):
    import witnessos_verifier.cert_chain as chain
    def unavailable(*args, **kwargs):
        raise FileNotFoundError('openssl unavailable')
    monkeypatch.setattr(chain.subprocess, 'run', unavailable)
    r = verify_timestamp(bundle_path/'timestamp/batch_timestamp.tsr', imprint(bundle_path), tsa_policy, TSA)
    assert not r.valid and not r.signature_verified


def test_retention_key_must_not_be_bundle_key(controlled_e4):
    p, policy, _ = controlled_e4
    data = json.loads((p/'keys.json').read_text())
    records = data if isinstance(data, list) else data['keys']
    policy = replace(policy, retention_authorities={'TEST-CUSTODIAN-NOT-PRODUCTION': records[0]['public_key_hex']})
    r = verify(p, trust_policy=policy, tsa_url=TSA)
    assert not r.worm_result.retention_verified
    assert any('independent of bundle signing keys' in e for e in r.errors)


def test_e4_json_cli_and_alpha(controlled_e4, tmp_path):
    from click.testing import CliRunner
    from witnessos_verifier.cli import main
    p, policy, _ = controlled_e4
    config = tmp_path/'operator.json'
    config.write_text(json.dumps(dict(level='standard', allowed_tsa_urls=[TSA],
                      trusted_roots=[str(q.resolve()) for q in policy.trusted_roots],
                      untrusted_certificates=[str(q.resolve()) for q in policy.untrusted_certificates],
                      retention_authorities=policy.retention_authorities)))
    runner = CliRunner()
    args = ['verify', str(p), '--trust-policy', str(config), '--tsa-url', TSA, '--json']
    r = runner.invoke(main, args)
    assert r.exit_code == 0, r.output
    obj = json.loads(r.output)
    assert obj['grade'] == 'E4' and obj['timestamp_signature_verified'] and obj['retention_verified']
    alpha = runner.invoke(main, [*args, '--alpha'])
    assert alpha.exit_code == 0 and json.loads(alpha.output)['grade'] == 'E3'
    inside = p/'policy.json'; shutil.copy(config, inside)
    denied = runner.invoke(main, ['verify', str(p), '--trust-policy', str(inside)])
    assert denied.exit_code == 2 and 'outside' in denied.output
