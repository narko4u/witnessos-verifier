"""Verifier-side adapter onto the canonical corroboration appraisal.

This module converts the verifier's own structures (events, key registry,
manifest, trust policy) into the canonical context, and does nothing else. It
holds no grade policy: whether corroboration is satisfied is decided by
`provider_attestation.verify`, the same function the engine calls.

Three transport shapes arrive here and leave as the same facts:

  1. a canonical provider attestation block
  2. a pre-canonical compatibility block
  3. a provider-signed acknowledgement event
"""
from __future__ import annotations

import base64
from typing import Iterable, Mapping, Optional

from . import provider_attestation as pa
from .case_tree import case_root, signature_bytes

PRIMARY_ACTION_TYPES = {
    "action.executed",
    "action_executed",
    "action.completed",
    "action_completed",
}
_FOLLOW_ON_EFFECTS = {
    "dispatch.started",
    "dispatch.completed",
    "dispatch.blocked",
    "credential.brokered",
    "credential_brokered",
}

__all__ = ["assess_corroboration", "normalise_events"]


def _to_dict(event) -> dict:
    if isinstance(event, Mapping):
        return dict(event)
    for method in ("model_dump", "dict", "_asdict"):
        dump = getattr(event, method, None)
        if callable(dump):
            try:
                return dict(dump())
            except Exception:  # pragma: no cover - defensive
                pass
    return {key: value for key, value in vars(event).items() if not key.startswith("_")}


def normalise_events(events: Iterable) -> list:
    return [_to_dict(event) for event in events]


def _provider_keys(policy, registry) -> dict:
    """Public key hex -> provider identity, from the trust policy."""
    out = {}
    sources = [
        getattr(policy, "provider_keys", None),
        getattr(policy, "providers", None),
    ]
    for source in sources:
        if isinstance(source, Mapping):
            for key, value in source.items():
                if isinstance(value, Mapping):
                    identity = value.get("identity") or value.get("name")
                    public = value.get("public_key_hex") or key
                else:
                    identity, public = value, key
                if isinstance(public, str) and isinstance(identity, str) and identity.strip():
                    out[public.lower()] = identity
    # A policy may state a single provisioned provider instead of a map.
    single_key = getattr(policy, "provider_public_key_hex", None) or getattr(
        policy, "provider_key_hex", None
    )
    single_identity = getattr(policy, "provider_identity", None) or getattr(
        policy, "provider_name", None
    )
    if isinstance(single_key, str) and isinstance(single_identity, str):
        out.setdefault(single_key.lower().replace("sha256:", ""), single_identity)
    return out


def _deployment_keys(normalised, manifest, registry) -> tuple:
    """(known, key ids, public key hexes) for keys the deployment itself used.

    The batch signer counts, and any key that signed a non-acknowledgement
    event counts. Identifiers are labels chosen by the bundle author, so where
    an identifier resolves to a public key through the bundle's registry the
    hex decides.
    """
    from .corroboration import PROVIDER_ACK_TYPES  # deferred: a module-level pair would cycle

    ids, hexes = set(), set()

    def resolve(key_id):
        if not isinstance(key_id, str) or not key_id:
            return
        ids.add(key_id)
        if registry is None:
            return
        getter = getattr(registry, "get_key", None)
        record = getter(key_id) if callable(getter) else None
        public = None
        if isinstance(record, Mapping):
            public = record.get("public_key_hex")
        elif record is not None:
            public = getattr(record, "public_key_hex", None)
        if isinstance(public, str) and public:
            hexes.add(public.lower().replace("sha256:", ""))

    signing = getattr(manifest, "signing_key_id", None)
    resolve(signing)
    for event in normalised:
        if event.get("event_type") in PROVIDER_ACK_TYPES:
            continue
        signed = event.get("signed") if isinstance(event.get("signed"), Mapping) else {}
        resolve(signed.get("signer_key_id") or signed.get("key_id"))
    return registry is not None, ids, hexes


def _signature_bytes(value) -> Optional[bytes]:
    """Accept base64 (canonical) or '<label>:<hex>' (wire) proof encodings."""
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    if ":" in value:
        label, _, body = value.partition(":")
        try:
            return bytes.fromhex(body)
        except ValueError:
            return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def _envelope_verifier(provider_keys):
    """Identity-first verifier: claimed provider, then its provisioned key(s).

    The signature never chooses the identity. The claimed `provider_id` is
    resolved through the trust policy to the keys provisioned for that identity,
    and only those keys are tried. A key belonging to another provisioned
    provider cannot make this bundle into this provider's evidence.
    """

    def verify(ack: Mapping, key_id: str, claimed_identity: str) -> tuple:
        claimed = str(claimed_identity or "").strip()
        if not claimed:
            return False, None
        allowed = [hex_value for hex_value, identity in provider_keys.items() if identity == claimed]
        if not allowed:
            return False, None
        signature = _signature_bytes(ack.get("signature"))
        if not signature and isinstance(ack.get("signed"), Mapping):
            signature = _signature_bytes(ack["signed"].get("signature"))
        if not signature:
            return False, None
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        message = signature_bytes(ack)
        for public in allowed:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(signature, message)
            except (InvalidSignature, ValueError, TypeError):
                continue
            return True, public
        return False, None

    return verify


def assess_corroboration(events, registry=None, manifest=None, policy=None, context_events=None):
    # Imported here, not at module scope: corroboration calls back into this module
    # for the canonical appraisal, and a module-level pair of imports would be a
    # cycle CodeQL flags (and Python resolves by accident of import order).
    from .corroboration import CorroborationResult, PROVIDER_ACK_TYPES

    """Appraise the record set against the canonical corroboration contract.

    `context_events` lets a caller appraise a historical prefix (what existed when
    an acknowledgement was recorded) while judging independence over the whole
    record. Independence is a property of the deployment and does not change
    because a later event exists; coverage is a property of the prefix and does.
    Conflating the two lets an acknowledgement look independent at prefix time and
    turn out to share a deployment key once the rest of the case arrives.
    """
    normalised = normalise_events(events)
    context = normalise_events(context_events) if context_events is not None else normalised
    ack_indices = [
        index
        for index, event in enumerate(normalised)
        if event.get("event_type") in PROVIDER_ACK_TYPES
    ]
    if not ack_indices:
        return CorroborationResult(
            present=False, reasons=("no provider acknowledgement event in the bundle",)
        )

    provider_keys = _provider_keys(policy, registry)
    deployment_known, deployment_ids, deployment_hexes = _deployment_keys(
        context, manifest, registry
    )
    envelope_verifier = _envelope_verifier(provider_keys)

    results = []
    covered = set()
    # One provider object cannot substantiate two governed actions. The usage map
    # must outlive a single acknowledgement, or every claim starts with an empty
    # history and the same authentic record corroborates both.
    record_usage: dict = {}
    # A rejected attestation still says which action it claimed. Keeping that
    # attribution is what lets the verdict name the property that failed instead
    # of reporting a bare "no acknowledgement" for the action it was aimed at.
    rejected: dict = {}
    for index in ack_indices:
        ack = normalised[index]
        payload = ack.get("payload") if isinstance(ack.get("payload"), Mapping) else {}
        attestation, shape = pa.normalise(payload, ack)
        if attestation is None:
            results.append(
                CorroborationResult(
                    present=True,
                    reasons=(
                        "acknowledgement carries no provider corroboration attestation and is "
                        "not provider-signed: it is the deployment's own record",
                    ),
                )
            )
            continue
        prefix = [e for e in normalised if int(e.get("seq", 0)) < int(ack.get("seq", 0))]
        # One commitment algorithm, no alternatives: the V1 canonical bytes of
        # every event strictly before the acknowledgement, in sequence order.
        expected_root = case_root(prefix) if prefix else None
        context = pa.Context(
            ack=ack,
            events=normalised,
            provider_keys=provider_keys,
            deployment_key_ids=deployment_ids,
            deployment_key_hexes=deployment_hexes,
            provider_records=pa.load_provider_records(),
            expected_root=expected_root,
            deployment_known=deployment_known,
            envelope_verifier=envelope_verifier,
            record_usage=record_usage,
        )
        facts = pa.verify(attestation, context)
        if facts.satisfied:
            covered.add(str(attestation.get("action_event_id")))
        elif facts.reasons:
            rejected[str(attestation.get("action_event_id"))] = tuple(facts.reasons)
        results.append(
            CorroborationResult(
                present=True,
                source_party=attestation.get("provider_id"),
                source_type=attestation.get("adapter_id") or attestation.get("authentication", {}).get("method"),
                source_record_id=facts.source_record_id,
                source_record_digest=attestation.get("provider_record_digest"),
                signer_identity=facts.provider_identity,
                signer_identity_verified=facts.provider_identity_verified,
                independent_of_deployment=facts.independent_of_deployment,
                subject_binding_valid=facts.subject_binding_valid and facts.outcome_binding_valid,
                provenance_verified=facts.provenance_verified,
                replay_check_passed=facts.replay_check_passed,
                cryptographic_integrity_valid=facts.cryptographic_integrity_valid,
                reasons=facts.reasons,
            )
        )

    satisfied = [result for result in results if result.satisfied]
    if not satisfied:
        reasons = []
        for result in results:
            reasons.extend(result.reasons)
        return CorroborationResult(present=True, reasons=tuple(dict.fromkeys(reasons)))

    action_events = [e for e in normalised if e.get("event_type") in PRIMARY_ACTION_TYPES]
    if not action_events:
        action_events = [
            e
            for e in normalised
            if e.get("event_type") in pa.ACTION_EFFECT_TYPES
            and e.get("event_type") not in _FOLLOW_ON_EFFECTS
        ]
    uncovered = [
        str(event.get("event_id"))
        for event in action_events
        if str(event.get("event_id")) not in covered
    ]
    best = satisfied[0]
    if uncovered:
        return CorroborationResult(
            present=True,
            source_party=best.source_party,
            source_type=best.source_type,
            source_record_id=best.source_record_id,
            source_record_digest=best.source_record_digest,
            signer_identity=best.signer_identity,
            signer_identity_verified=best.signer_identity_verified,
            independent_of_deployment=best.independent_of_deployment,
            subject_binding_valid=False,
            provenance_verified=best.provenance_verified,
            replay_check_passed=best.replay_check_passed,
            cryptographic_integrity_valid=best.cryptographic_integrity_valid,
            reasons=(
                f"{len(uncovered)} action event(s) in this record set have no acknowledgement: "
                + ", ".join(uncovered),
            )
            + tuple(
                f"{action_id}: {reason}"
                for action_id, reasons_for in rejected.items()
                for reason in reasons_for
            ),
        )
    return best
