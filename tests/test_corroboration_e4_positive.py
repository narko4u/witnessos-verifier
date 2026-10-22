# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Positive control: the top of the ladder is still reachable.

A bundle whose acknowledgement is signed by a second key, attributed to the
provider by the operator's trust policy, naming the provider's own record and
committing to the action's record set, reaches E3. With an RFC 3161 token over
its root and an authenticated retention receipt it reaches E4.

The token here is minted locally by a throwaway CA under an operator-provided
root. That is the same trust route a production deployment uses with a public
TSA: the verifier does not care who the TSA is, only that the operator named it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import nacl.signing
import pytest
from asn1crypto import tsp

from tests.hostile import factory
from tests.test_adversarial_bundle import rehash_worm
from tests.test_authenticated_e4 import make_test_custody_receipt
from witnessos_verifier.trust_policy import TrustLevel
from witnessos_verifier.verifier import verify

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI required")


def _run(*args, cwd=None):
    subprocess.run(args, check=True, capture_output=True, cwd=cwd)


def _mint_tsa(tmp_path: Path) -> tuple[Path, Path]:
    """Throwaway CA with a timeStamping signer. Never used outside this test."""
    ca_key, ca_pem = tmp_path / "ca.key", tmp_path / "ca.pem"
    tsa_key, tsa_csr, tsa_pem = tmp_path / "tsa.key", tmp_path / "tsa.csr", tmp_path / "tsa.pem"
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca_pem), "-subj", "/CN=WitnessOS Test TSA CA", "-days", "3650",
         "-addext", "basicConstraints=critical,CA:TRUE")
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tsa_key),
         "-out", str(tsa_csr), "-subj", "/CN=WitnessOS Test TSA")
    ext = tmp_path / "tsa.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=critical,timeStamping\n"
    )
    _run("openssl", "x509", "-req", "-in", str(tsa_csr), "-CA", str(ca_pem), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(tsa_pem), "-days", "3650", "-extfile", str(ext))
    return ca_pem, tsa_pem


def _anchor(tmp_path: Path, bundle: Path, ca_pem: Path, tsa_pem: Path, tsa_url: str) -> nacl.signing.SigningKey:
    root = bytes.fromhex(json.loads((bundle / "batch_manifest.json").read_text())["root"])
    data = tmp_path / "root.bin"
    data.write_bytes(root)
    query, reply = tmp_path / "req.tsq", tmp_path / "resp.tsr"
    _run("openssl", "ts", "-query", "-data", str(data), "-sha256", "-cert", "-out", str(query))
    _run("openssl", "ts", "-reply", "-queryfile", str(query),
         "-signer", str(tsa_pem), "-inkey", str(tmp_path / "tsa.key"),
         "-chain", str(ca_pem), "-out", str(reply))
    (bundle / "timestamp").mkdir(exist_ok=True)
    canonical = tsp.TimeStampResp.load(reply.read_bytes(), strict=True).dump(force=True)
    (bundle / "timestamp" / "batch_timestamp.tsr").write_bytes(canonical)

    (bundle / "worm").mkdir(exist_ok=True)
    (bundle / "worm" / "batch_store.json").write_text(json.dumps({
        "batch_id": "batch_audit_001",
        "stored_at": "2026-10-21T00:00:00Z",
        "case_id": "case_audit_001",
    }))
    sk = nacl.signing.SigningKey.generate()
    make_test_custody_receipt(bundle, sk)
    rehash_worm(bundle)
    return sk


def test_corroborated_bundle_reaches_e4_with_a_real_anchor(tmp_path):
    built = factory.build(tmp_path / "corroborated")
    ca_pem, tsa_pem = _mint_tsa(tmp_path)
    tsa_url = "https://tsa.audit.local/tsr"
    custodian = _anchor(tmp_path, built["path"], ca_pem, tsa_pem, tsa_url)

    policy = replace(
        factory.policy(built["provider_public_hex"]),
        level=TrustLevel.STANDARD,
        allowed_tsa_urls={tsa_url},
        trusted_roots=[ca_pem],
        untrusted_certificates=[tsa_pem],
        retention_authorities={"TEST-CUSTODIAN-NOT-PRODUCTION": bytes(custodian.verify_key).hex()},
    )
    result = verify(built["path"], trust_policy=policy, tsa_url=tsa_url)

    assert result.valid, result.errors
    assert result.corroboration.satisfied
    assert result.timestamp_result.trust_verified
    assert result.worm_result.retention_verified
    assert result.evidence_grade == "E4", result.grade.requirements_missing


def test_same_anchor_on_uncorroborated_bundle_stays_at_e2(tmp_path):
    """The identical token and receipt over a self-signed acknowledgement."""
    built = factory.build(tmp_path / "self-signed", ack="self")
    ca_pem, tsa_pem = _mint_tsa(tmp_path)
    tsa_url = "https://tsa.audit.local/tsr"
    custodian = _anchor(tmp_path, built["path"], ca_pem, tsa_pem, tsa_url)

    policy = replace(
        factory.policy(built["deployment_public_hex"]),
        level=TrustLevel.STANDARD,
        allowed_tsa_urls={tsa_url},
        trusted_roots=[ca_pem],
        untrusted_certificates=[tsa_pem],
        retention_authorities={"TEST-CUSTODIAN-NOT-PRODUCTION": bytes(custodian.verify_key).hex()},
    )
    result = verify(built["path"], trust_policy=policy, tsa_url=tsa_url)

    assert result.timestamp_result.trust_verified
    assert result.worm_result.retention_verified
    assert result.evidence_grade == "E2", result.grade.requirements_met
