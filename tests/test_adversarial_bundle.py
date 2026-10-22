# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Launch-blocking attacks. Mutations affect disposable copies, never fixtures."""
import hashlib
import json
import shutil

import pytest

from witnessos_verifier.verifier import verify


def rehash_worm(p):
    files = sorted(f for f in p.rglob('*') if f.is_file() and 'worm' not in f.relative_to(p).parts)
    store = p / 'worm/batch_store.json'
    data = json.loads(store.read_text())
    data['stored_hash'] = hashlib.sha256(b''.join(f.read_bytes() for f in files)).hexdigest()
    data['file_count'] = len(files)
    data['file_hashes'] = {str(f.relative_to(p)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    store.write_text(json.dumps(data))


@pytest.mark.parametrize('attack', ['last_payload', 'last_signature', 'delete_proof', 'fake_proof', 'timestamp_signature', 'truncate_events', 'malformed_manifest'])
def test_reject_attacker_bundle(bundle_path, tmp_path, attack):
    p = tmp_path / 'bundle'
    shutil.copytree(bundle_path, p)
    events = sorted((p / 'events').glob('*.json'))
    if attack.startswith('last_'):
        data = json.loads(events[-1].read_text())
        if attack == 'last_payload':
            data['payload']['attacker'] = 'forged action'
        else:
            data['signed']['signature'] = 'AAAA'
        events[-1].write_text(json.dumps(data))
    elif attack == 'delete_proof':
        (p / 'merkle_proof.json').unlink()
    elif attack == 'fake_proof':
        (p / 'merkle_proof.json').write_text('{}')
    elif attack == 'timestamp_signature':
        token = p / 'timestamp/batch_timestamp.tsr'
        b = bytearray(token.read_bytes()); b[-1] ^= 1; token.write_bytes(b)
    elif attack == 'truncate_events':
        events[-1].unlink()
    elif attack == 'malformed_manifest':
        (p / 'batch_manifest.json').write_text('{')
    rehash_worm(p)
    result = verify(p)
    print(f'{attack}: valid={result.valid}, grade={result.evidence_grade}')
    assert not result.valid
    assert result.evidence_grade != 'E4'


@pytest.mark.parametrize('name', ['e4-gmail-approved-send', 'e4-stripe-refund'])
def test_real_event_signatures_both_vocabularies(bundle_path, name):
    from witnessos_verifier.binding import verify_event_signatures
    from witnessos_verifier.events import load_events
    from witnessos_verifier.key_registry import KeyRegistry
    p = bundle_path.parent / name
    assert verify_event_signatures(load_events(p), KeyRegistry.from_file(p / 'keys.json')) == []


def test_signature_attack_is_detected_independently(bundle_path):
    from witnessos_verifier.binding import verify_event_signatures
    from witnessos_verifier.events import load_events
    from witnessos_verifier.key_registry import KeyRegistry
    events = load_events(bundle_path)
    events[-1].payload['forged'] = True
    assert verify_event_signatures(events, KeyRegistry.from_file(bundle_path / 'keys.json'))


@pytest.mark.parametrize('vocab', ['provider.acknowledged', 'provider.confirmed', 'provider_acknowledged', 'provider_confirmed'])
def test_all_ack_vocabulary(vocab):
    from witnessos_verifier.verifier import PROVIDER_ACK_TYPES
    assert vocab in PROVIDER_ACK_TYPES


@pytest.mark.parametrize(
    'field,expected',
    [
        ('events_loaded', 'E0'),
        ('observation_external', 'E0'),
        ('event_signatures_valid', 'E1'),
        ('batch_binding_valid', 'E1'),
        ('enforcement_observed', 'E1'),
        ('corroboration', 'E2'),
    ],
)
def test_cumulative_ladder(field, expected):
    from types import SimpleNamespace as R
    from witnessos_verifier.corroboration import CorroborationResult
    from witnessos_verifier.grades import derive_grade
    satisfied = CorroborationResult(
        present=True,
        signer_identity="Stripe",
        signer_identity_verified=True,
        independent_of_deployment=True,
        subject_binding_valid=True,
        provenance_verified=True,
        replay_check_passed=True,
        cryptographic_integrity_valid=True,
    )
    args = dict(events_loaded=True, event_signatures_valid=True, batch_binding_valid=True, merkle_proof_valid=True,
                observation_external=True, enforcement_observed=True,
                chain_result=R(valid=True), ledger_result=R(valid=True, sequence_monotonic=True),
                manifest_result=R(valid=True), corroboration=satisfied,
                timestamp_result=R(valid=True, imprint_matches=True, signature_verified=True, trust_verified=True),
                worm_result=R(valid=True, retention_verified=True))
    assert derive_grade(**args).grade == 'E4'
    args[field] = None if field == 'corroboration' else False
    assert derive_grade(**args).grade == expected


def test_parsing_and_checksums_do_not_make_e4():
    from types import SimpleNamespace as R
    from witnessos_verifier.corroboration import CorroborationResult
    from witnessos_verifier.grades import derive_grade
    satisfied = CorroborationResult(
        present=True,
        signer_identity="Stripe",
        signer_identity_verified=True,
        independent_of_deployment=True,
        subject_binding_valid=True,
        provenance_verified=True,
        replay_check_passed=True,
        cryptographic_integrity_valid=True,
    )
    result = derive_grade(True, R(valid=True), R(valid=True, sequence_monotonic=True),
                          R(valid=True), satisfied, R(valid=True, imprint_matches=True), R(valid=True),
                          event_signatures_valid=True, batch_binding_valid=True,
                          observation_external=True, enforcement_observed=True)
    assert result.grade == 'E3'
