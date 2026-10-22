# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""The canonical corroboration contract, exercised from first principles.

Finding 10: the engine and the public verifier must appraise the same evidence
the same way. The fixtures here carry a canonical `provider_corroboration`
block, signed by the provider over the canonical V1 bytes, and every case
asserts the specific property that failed as well as the grade ceiling, so a
future change cannot produce the right grade for the wrong reason.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from witnessos_verifier import provider_attestation as pa
from witnessos_verifier.appraisal import assess_corroboration

from .hostile import factory

DEPLOYMENT_SEED = factory.SEEDS["deployment"]
PROVIDER_SEED = factory.SEEDS["provider"]
OTHER_SEED = factory.SEEDS["unprovisioned"]
SAME_DEPLOYMENT_SEED = factory.SEEDS["same_deployment"]

PROVIDER_HEX = factory.public_hex("provider")
OTHER_HEX = factory.public_hex("unprovisioned")
SAME_DEPLOYMENT_HEX = factory.public_hex("same_deployment")
DEPLOYMENT_HEX = factory.public_hex("deployment")

CASE = "case_canonical_001"
CONFIRMED = "provider.confirmed"


class _Record:
    def __init__(self, public_key_hex: str):
        self.public_key_hex = public_key_hex


class _Registry:
    """The deployment's own key registry: it holds the deployment's keys."""

    def __init__(self, mapping):
        self._mapping = mapping

    def get_key(self, key_id):
        return self._mapping.get(key_id)


def _registry(extra: dict | None = None) -> _Registry:
    mapping = {
        "key_deployment": _Record(DEPLOYMENT_HEX),
        "key_same_deployment": _Record(SAME_DEPLOYMENT_HEX),
    }
    if extra:
        mapping.update(extra)
    return _Registry(mapping)


def _policy(provider_hex: str = PROVIDER_HEX) -> object:
    return factory.policy(provider_hex)


def _sign(role: str, message: bytes) -> str:
    """Base64 Ed25519 signature, the wire form the verifier reads."""
    import base64

    return base64.b64encode(factory.signing_key(role).sign(message).signature).decode()


def _signed_event(seq: int, event_type: str, payload: dict, prev_hash: str, role: str, signer_id: str):
    event = {
        "event_id": f"evt_c_{seq:04d}",
        "event_type": event_type,
        "case_id": CASE,
        "seq": seq,
        "prev_hash": prev_hash,
        "payload": payload,
    }
    event["signed"] = {
        "signer_key_id": signer_id,
        "algorithm": "Ed25519",
        "signature": _sign(role, factory.canonical(event)),
        "signed_headers": factory.HEADERS,
    }
    return event


def _attestation(**overrides) -> dict:
    attestation = {
        "version": pa.DOMAIN,
        "provider_id": factory.PROVIDER_IDENTITY,
        "acknowledgement_event_id": "evt_c_0003",
        "acknowledgement_type": CONFIRMED,
        "case_id": CASE,
        "action_event_id": "evt_c_0002",
        "action_event_type": "action_executed",
        "outcome": "succeeded",
        "provider_record_id": "ch_canonical_record_1",
        "provider_record_digest": hashlib.sha256(b"canonical-record-1").hexdigest(),
        "prior_events_root": "",
        "authentication": {"method": "native_signature", "key_id": PROVIDER_HEX},
    }
    attestation.update(overrides)
    return attestation


def _proof(attestation: dict, role: str = "provider") -> str:
    return _sign(role, pa.signing_bytes(attestation))


def build_case(attestation: dict | None = None, proof_role: str = "provider", action_role: str = "deployment"):
    """E1 observation, E2 enforcement, action, then the provider acknowledgement."""
    events = [
        _signed_event(0, "observation.recorded", {"subject": "payment"}, factory.GENESIS, "deployment", "key_deployment"),
        _signed_event(1, "policy.enforced", {"policy": "refund-limit"}, "", "deployment", "key_deployment"),
    ]
    events[1]["prev_hash"] = hashlib.sha256(factory.canonical(events[0])).hexdigest()
    events.append(
        _signed_event(2, "action_executed", {"amount": 1200, "outcome": "succeeded"}, hashlib.sha256(factory.canonical(events[1])).hexdigest(), action_role, f"key_{action_role}")
    )
    attestation = dict(attestation or _attestation())
    if not attestation.get("prior_events_root"):
        from witnessos_verifier.case_tree import case_root

        attestation["prior_events_root"] = case_root(events)
    attestation["authentication"] = dict(attestation["authentication"])
    if not attestation["authentication"].get("proof"):
        attestation["authentication"]["proof"] = _proof(attestation, proof_role)
    ack = _signed_event(
        3,
        CONFIRMED,
        {"provider_corroboration": attestation},
        hashlib.sha256(factory.canonical(events[2])).hexdigest(),
        "provider",
        "key_provider",
    )
    events.append(ack)
    return events, attestation


def appraise(events, policy=None, registry=None):
    return assess_corroboration(events, registry or _registry(), None, policy or _policy())


def test_canonical_block_reaches_e3():
    events, _ = build_case()
    result = appraise(events)
    assert result.satisfied, result.reasons
    assert result.signer_identity == factory.PROVIDER_IDENTITY
    assert result.signer_identity_verified is True
    assert result.independent_of_deployment is True
    assert result.subject_binding_valid is True
    assert result.replay_check_passed is True
    assert result.cryptographic_integrity_valid is True


# Record id and digest are deliberately absent from this table: judging them
# requires a provider adapter that can read the provider (Finding 12). Without
# one, the most a verifier can say is that the provider signed that digest.
# Failure properties, one per hostile case. Each entry states the mutation and
# the single property expected to fail, so the ceiling is never reached by luck.
HOSTILE = {
    "wrong_acknowledgement_id": ({"acknowledgement_event_id": "evt_c_9999"}, "subject_binding_valid"),
    "wrong_acknowledgement_type": ({"acknowledgement_type": "provider.noted"}, "subject_binding_valid"),
    "wrong_case": ({"case_id": "case_other"}, "subject_binding_valid"),
    "wrong_action_id": ({"action_event_id": "evt_c_0001"}, "subject_binding_valid"),
    "wrong_action_type": ({"action_event_type": "policy.enforced"}, "subject_binding_valid"),
    "wrong_outcome": ({"outcome": "failed"}, "subject_binding_valid"),
    "wrong_prior_root": ({"prior_events_root": hashlib.sha256(b"other-batch").hexdigest()}, "replay_check_passed"),
    "untrusted_provider_key": (
        {"authentication": {"method": "native_signature", "key_id": OTHER_HEX}},
        "signer_identity_verified",
    ),
    "unknown_authentication_method": (
        {"authentication": {"method": "telepathy", "key_id": "key_provider"}},
        "cryptographic_integrity_valid",
    ),
    "mac_without_probe": (
        {"authentication": {"method": "mac", "key_id": "key_provider"}},
        "independent_of_deployment",
    ),
}


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_hostile_canonical_case_fails_closed(case):
    overrides, failed_property = HOSTILE[case]
    attestation = _attestation(**overrides)
    if "authentication" in overrides:
        # Keep the block internally consistent so the property under test is the
        # only obstacle: the mutation is the sole difference from the honest case.
        attestation["authentication"] = dict(overrides["authentication"])
        attestation["authentication"]["proof"] = _proof(attestation)
    events, _ = build_case(attestation=attestation)
    result = appraise(events)
    assert not result.satisfied, f"{case} reached E3: {result.reasons}"
    assert getattr(result, failed_property) is False, (
        f"{case} failed for the wrong reason: {failed_property} is True, reasons={result.reasons}"
    )


def test_tampered_proof_fails_closed():
    attestation = _attestation()
    events, _ = build_case(attestation=attestation)
    ack = events[-1]
    block = ack["payload"]["provider_corroboration"]
    block["authentication"]["proof"] = _proof(_attestation(outcome="refunded"))
    result = appraise(events)
    assert not result.satisfied
    assert result.cryptographic_integrity_valid is False


def test_later_event_cannot_be_covered():
    """An action recorded after the acknowledgement is a different claim."""
    events, _ = build_case()
    later = _signed_event(4, "action_executed", {"amount": 5}, factory.GENESIS, "deployment", "key_deployment")
    result = appraise(events + [later])
    assert not result.satisfied
    assert "no acknowledgement" in " ".join(result.reasons)


def test_same_deployment_key_cannot_be_the_provider():
    attestation = _attestation(
        provider_id="SameDeployment",
        authentication={"method": "native_signature", "key_id": SAME_DEPLOYMENT_HEX},
    )
    events, _ = build_case(
        attestation=attestation, proof_role="same_deployment", action_role="same_deployment"
    )
    result = appraise(events, policy=_policy(SAME_DEPLOYMENT_HEX))
    assert not result.satisfied
    assert result.independent_of_deployment is False


def test_provider_label_and_key_must_agree():
    """A block may name any provider; the key must be provisioned to that name."""
    attestation = _attestation(provider_id="SomeoneElse")
    events, _ = build_case(attestation=attestation)
    result = appraise(events)
    assert not result.satisfied
    assert result.signer_identity_verified is False


def test_replayed_attestation_over_a_second_action_fails():
    """The same authenticated attestation moved to another action is refused."""
    events, attestation = build_case()
    ack = events[-1]
    replayed = dict(attestation)
    replayed["action_event_id"] = "evt_c_0000"
    replayed["authentication"] = dict(attestation["authentication"])
    replayed["authentication"]["proof"] = _proof(replayed)
    ack["payload"]["provider_corroboration"] = replayed
    result = appraise(events)
    assert not result.satisfied
    assert result.subject_binding_valid is False


def test_missing_adapter_for_delegated_method_fails_closed():
    attestation = _attestation(authentication={"method": "probe", "key_id": PROVIDER_HEX})
    events, _ = build_case(attestation=attestation)
    result = appraise(events)
    assert not result.satisfied
    assert result.cryptographic_integrity_valid is False


def test_unreadable_registry_fails_closed():
    events, _ = build_case()
    result = assess_corroboration(events, None, None, _policy())
    assert not result.satisfied
    assert result.independent_of_deployment is False
