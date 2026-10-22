# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Deterministic hostile and honest bundle factory for the grade audit.

Every bundle here is produced by test code, not by the engine, so an attacker
model is explicit: one party writes every file, holds every private key it uses
and publishes the matching public keys itself. Keys come from fixed seeds so a
bundle is reproducible byte for byte.

The variable that decides the grade is never a bundle field. It is which key
signed the acknowledgement and whether the verifier's own trust policy
attributes that key to another party.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Optional

import nacl.signing

from witnessos_verifier.merkle import build_merkle_tree, inclusion_proof, leaf_hash
from witnessos_verifier.trust_policy import TrustLevel, TrustPolicy

HEADERS = ["case_id", "event_id", "event_type", "payload", "prev_hash", "seq"]
GENESIS = hashlib.sha256(b"").hexdigest()
CASE_ID = "case_audit_001"
# The identity the operator provisions and the identity the evidence claims must
# be the same string. A bundle that claims "stripe" while the operator
# provisions "Stripe-test" is claiming an identity nobody provisioned.
PROVIDER_IDENTITY = "Stripe-test"

SEEDS = {
    "deployment": b"\x01" * 32,
    "provider": b"\x02" * 32,
    "same_deployment": b"\x03" * 32,
    "unprovisioned": b"\x04" * 32,
    "custodian": b"\x05" * 32,
}


def signing_key(role: str) -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(SEEDS[role])


def public_hex(role: str) -> str:
    return bytes(signing_key(role).verify_key).hex()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _write(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=1, sort_keys=True) + "\n")


def policy(provider_hex: Optional[str] = None, identity: str = "Stripe-test") -> TrustPolicy:
    """Operator-provisioned trust input. Nothing here is read from a bundle."""
    return TrustPolicy(
        level=TrustLevel.DEMO,
        provider_keys={provider_hex: identity} if provider_hex else {},
    )


def _event(seq: int, event_type: str, payload: dict, prev_hash: str, signer: str) -> dict:
    event = {
        "event_id": f"evt_audit_{seq:04d}",
        "event_type": event_type,
        "case_id": CASE_ID,
        "seq": seq,
        "prev_hash": prev_hash,
        "payload": payload,
    }
    signature = signing_key(signer).sign(canonical(event)).signature
    event["signed"] = {
        "signer_key_id": f"key_{signer}",
        "algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode(),
        "signed_headers": HEADERS,
    }
    return event


def build(
    out: Path,
    *,
    ack: str = "independent",
    provider_event: str = "provider.confirmed",
    provider_ref: bool = True,
    subject_binding: bool = True,
    replay_binding: bool = True,
    self_digest: bool = False,
    enforcement: bool = True,
    observation: bool = True,
    declared_grade: Optional[str] = None,
    custody_label: Optional[str] = None,
    tamper_ack_after_sign: bool = False,
) -> dict:
    """Build a bundle. Returns the path plus every public key involved."""
    out = Path(out)
    (out / "events").mkdir(parents=True, exist_ok=True)

    plan = []
    if observation:
        plan.append(("action_requested", {"action": "refund", "amount": 42}))
        if enforcement:
            plan.append(
                (
                    "policy_checked",
                    {"policy": "outbound-approval", "allowed": True, "permit_id": "permit_1"},
                )
            )
        plan.append(("dispatch.started", {"permit_id": "permit_1", "channel": "stripe"}))
    else:
        plan.append(("action_requested", {"action": "refund", "amount": 42}))

    ack_role = {
        "independent": "provider",
        "unprovisioned": "unprovisioned",
        "self": "deployment",
        "same_deployment": "same_deployment",
        "absent": None,
    }[ack]

    events: list = []
    prev_hash = GENESIS
    for seq, (event_type, payload) in enumerate(plan):
        events.append(_event(seq, event_type, payload, prev_hash, "deployment"))
        prev_hash = hashlib.sha256(canonical(events[-1])).hexdigest()

    if ack_role is not None:
        prefix = list(events)
        prefix_root = build_merkle_tree([leaf_hash(canonical(e)) for e in prefix]).hex()
        payload: dict = {"provider": PROVIDER_IDENTITY}
        # The provider asserts the substantive outcome it observed. It sits
        # inside the provider-signed envelope, so it is authenticated by the
        # signer rather than trusted from the payload's shape.
        payload["outcome"] = "succeeded"
        if custody_label:
            payload["custody"] = custody_label
            payload["basis_engine"] = "external_authority"
        if provider_ref:
            payload["provider_record_id"] = "ch_test_record_1"
            payload["provider_record_digest"] = hashlib.sha256(b"provider-record-1").hexdigest()
        if subject_binding:
            payload["subject"] = {
                "case_id": CASE_ID,
                "action_event_id": prefix[-1]["event_id"],
                "batch_root": prefix_root if replay_binding else hashlib.sha256(b"other-batch").hexdigest(),
            }
        elif replay_binding:
            payload["subject"] = {
                "case_id": "case_other",
                "action_event_id": prefix[-1]["event_id"],
                "batch_root": prefix_root,
            }
        if self_digest:
            # Self-reference: the acknowledgement names itself as the other
            # party's record, with a digest derived from its own payload.
            payload["provider_record_id"] = f"evt_audit_{len(prefix):04d}"
            payload["provider_record_digest"] = hashlib.sha256(canonical(payload)).hexdigest()
        seq = len(prefix)
        events.append(_event(seq, provider_event, payload, prev_hash, ack_role))
        prev_hash = hashlib.sha256(canonical(events[-1])).hexdigest()

    closing_signer = "deployment"
    if ack == "same_deployment":
        closing_signer = "same_deployment"
    if observation:
        events.append(
            _event(len(events), "case_closed", {"final_status": "closed"}, prev_hash, closing_signer)
        )

    for event in events:
        _write(out / "events" / f"{event['seq']:04d}_{event['event_id']}.json", event)

    keys = ["deployment"]
    if ack in ("independent", "unprovisioned", "same_deployment"):
        keys.append(ack_role)
    _write(
        out / "keys.json",
        [
            {
                "key_id": f"key_{role}",
                "public_key_hex": public_hex(role),
                "status": "active",
                "algorithm": "Ed25519",
                "created_at": "2026-10-21T00:00:00Z",
                "description": "producer-published key",
            }
            for role in keys
        ],
    )

    leaves = [leaf_hash(canonical(e)) for e in events]
    root = build_merkle_tree(leaves)
    proof_index = len(events) - 1
    _write(
        out / "merkle_proof.json",
        {
            "leaf_index": proof_index,
            "tree_size": len(events),
            "leaf_hash": leaves[proof_index].hex(),
            "proof_hashes": [s.hex() for s in inclusion_proof(leaves, proof_index)],
            "root": root.hex(),
        },
    )
    _write(out / "case_manifest.json", {"case_id": CASE_ID, "event_count": len(events)})

    manifest = {
        "batch_id": "batch_audit_001",
        "signing_key_id": "key_deployment",
        "case_id": CASE_ID,
        "root": root.hex(),
        "prev_root": "",
        "event_ids": [e["event_id"] for e in events],
        "start_seq": events[0]["seq"],
        "end_seq": events[-1]["seq"],
        "signed_at": "2026-10-21T00:00:00Z",
    }
    # The verifier signs and checks a fixed field set, so a declared grade is
    # added after signing, exactly as a producer would add an echo field.
    signed_subset = {k: v for k, v in manifest.items() if k != "grade"}
    signature = signing_key("deployment").sign(canonical(signed_subset)).signature
    manifest["signature"] = base64.b64encode(signature).decode()
    if declared_grade:
        manifest["grade"] = declared_grade
    _write(out / "batch_manifest.json", manifest)

    if tamper_ack_after_sign:
        ack_files = [p for p in sorted((out / "events").glob("*.json")) if provider_event in p.read_text()]
        target = ack_files[-1]
        data = json.loads(target.read_text())
        data["payload"]["provider_record_id"] = "forged_after_signing"
        _write(target, data)

    return {
        "path": out,
        "provider_public_hex": public_hex("provider"),
        "unprovisioned_public_hex": public_hex("unprovisioned"),
        "deployment_public_hex": public_hex("deployment"),
        "same_deployment_public_hex": public_hex("same_deployment"),
    }
