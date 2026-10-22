# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Verifier-derived corroboration for E3.

An event whose type says a provider confirmed something is a claim by whoever
signed it. Until this module existed the grade derivation read that event type
as a fact, so a deployment could write `provider.confirmed`, sign it with its
own key, publish the key in its own `keys.json` and be graded E3, then E4 once
any anchor was added. Every one of those steps is producible by the party whose
evidence is being graded.

Corroboration is therefore an appraisal, never a field. This module answers one
question for the grade engine:

    is there an acknowledgement here that came from a party other than the
    deployment, whose identity the operator has established independently, which
    names the other party's own record, and which is bound to this action and
    this batch?

Every condition defaults to false and every failure is named. The function can
only observe; it cannot be told. A bundle carries no value that sets these
fields, and no boolean is accepted from a caller.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence

from .binding import verify_event_signatures
from .evidence_semantics import ACTION_TYPES
from .key_registry import KeyRegistry
from .manifest import BatchManifest
from .merkle import build_merkle_tree, leaf_hash
from .trust_policy import TrustPolicy

from .corroboration_types import PROVIDER_ACK_TYPES, CorroborationResult

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _norm_hex(value: object) -> Optional[str]:
    if isinstance(value, str) and _HEX64.match(value):
        return value.lower()
    return None


def _words(value: str) -> str:
    """Normalise a party label for comparison: lowercase words, single spaces."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _deployment_signers(
    events: Sequence, manifest: Optional[BatchManifest], registry: Optional[KeyRegistry] = None
) -> tuple[set, set]:
    """Public keys the deployment itself used to sign non-provider evidence.

    The batch signer is included. Any key that signed the record set belongs to
    the party being graded, so a provider acknowledgement bearing the same key
    is that party agreeing with itself.

    Returned as two sets: resolved public keys (hex) and the raw key identifiers.
    Comparing identifiers alone is not enough. A key identifier is a label the
    bundle author chooses and it sits outside the signed message, so the same
    public key registered twice under two labels would look like two parties.
    Where a key identifier resolves to a public key through the bundle's own
    registry the hex is compared as well, and the hex comparison is the one that
    decides.
    """
    ids: set = set()
    hexes: set = set()
    if manifest is not None:
        ids.add(manifest.signing_key_id)
        if registry is not None:
            record = registry.get_key(manifest.signing_key_id)
            resolved = _norm_hex(record.public_key_hex) if record is not None else None
            if resolved:
                hexes.add(resolved)
    for event in events:
        if event.event_type in PROVIDER_ACK_TYPES:
            continue
        signed = event.signed if isinstance(event.signed, dict) else {}
        key_id = signed.get("signer_key_id") or signed.get("key_id")
        if isinstance(key_id, str) and key_id:
            ids.add(key_id)
            if registry is not None:
                record = registry.get_key(key_id)
                resolved = _norm_hex(record.public_key_hex) if record is not None else None
                if resolved:
                    hexes.add(resolved)
    return ids, hexes


def _assess_one(event, events, registry, manifest, policy) -> CorroborationResult:
    reasons: List[str] = []
    payload = event.payload if isinstance(event.payload, dict) else {}

    # 1. Cryptographic integrity of this event, recomputed here rather than
    #    inherited from the batch-level flag.
    crypto_ok = not verify_event_signatures([event], registry)
    if not crypto_ok:
        reasons.append("acknowledgement signature does not verify")

    signed = event.signed if isinstance(event.signed, dict) else {}
    key_id = signed.get("signer_key_id") or signed.get("key_id")
    record = registry.get_key(key_id) if (registry and isinstance(key_id, str)) else None
    signer_hex = _norm_hex(record.public_key_hex) if record is not None else None

    # 2. Identity: the operator's provisioned map decides who a key belongs to.
    #    A key that appears only inside the bundle establishes nothing about
    #    who holds it.
    trusted = {
        _norm_hex(k): v
        for k, v in (getattr(policy, "provider_keys", {}) or {}).items()
        if _norm_hex(k)
    }
    identity = trusted.get(signer_hex) if signer_hex else None
    identity_ok = bool(identity)
    if not identity_ok:
        reasons.append(
            "signing key is not provisioned to a provider identity in the verifier trust policy"
        )

    # 3. Independence: a key the deployment also used for its own evidence is
    #    the deployment. Compared by public key where the registry resolves it,
    #    because a key identifier is a label the bundle author picks.
    deployment_ids, deployment_hexes = _deployment_signers(events, manifest, registry)
    same_key = (signer_hex is not None and signer_hex in deployment_hexes) or (
        isinstance(key_id, str) and key_id in deployment_ids
    )
    independent = identity_ok and not same_key
    if identity_ok and not independent:
        reasons.append("acknowledgement was signed by a key the deployment used for its own evidence")

    # 3b. The party the acknowledgement names must agree with the party the key
    #     was provisioned to. The provisioning label is the operator's own, so the
    #     comparison is on normalised words rather than exact strings: a label of
    #     "Stripe (test)" and a claim of "stripe" agree, a key provisioned to
    #     Stripe signing a claim that names someone else does not.
    claimed_party = payload.get("provider")
    if identity_ok and isinstance(claimed_party, str) and claimed_party.strip():
        claimed_norm = _words(claimed_party)
        identity_norm = _words(str(identity))
        agree = bool(claimed_norm) and bool(identity_norm) and (
            claimed_norm == identity_norm
            or claimed_norm in identity_norm
            or identity_norm in claimed_norm
        )
        if not agree:
            reasons.append(
                f"acknowledgement names {claimed_party.strip()!r} but the signing key is "
                f"provisioned to {identity!r}"
            )
            identity_ok = False
            independent = False

    # 4. Provenance: a reference to the other party's own record, with a digest.
    ref_id = payload.get("provider_record_id")
    ref_digest = payload.get("provider_record_digest")
    ref_id_ok = isinstance(ref_id, str) and bool(ref_id.strip()) and ref_id not in (
        event.event_id,
        event.case_id,
    )
    ref_digest_ok = isinstance(ref_digest, str) and bool(_HEX64.match(ref_digest))
    provenance_ok = ref_id_ok and ref_digest_ok
    if not provenance_ok:
        reasons.append("acknowledgement names no external record of its own (id and 64-hex digest)")
    elif isinstance(ref_digest, str) and ref_digest.strip().lower() == event.canonical_hash:
        provenance_ok = False
        reasons.append("acknowledgement cites its own hash as provenance")

    # 5. Subject binding: the acknowledgement must name this case and this
    #    action, and the exact batch it belongs to.
    raw_subject = payload.get("subject")
    subject: dict = raw_subject if isinstance(raw_subject, dict) else {}
    event_ids = {e.event_id: e for e in events}
    referenced = event_ids.get(subject.get("action_event_id") or "")
    binding_ok = (
        subject.get("case_id") == event.case_id
        and event.case_id == (manifest.case_id if manifest is not None else event.case_id)
        and referenced is not None
    )
    if binding_ok and referenced is not None:
        # The subject of a corroboration is an action or an effect. A policy
        # decision, an approval, an observation or an anchor is administrative,
        # and a provider did not perform it.
        if referenced.event_type not in ACTION_TYPES:
            binding_ok = False
            reasons.append(
                f"acknowledgement names {referenced.event_type}, which is not an action or effect event"
            )
        elif referenced.seq >= event.seq:
            binding_ok = False
            reasons.append("acknowledgement does not precede the event it names as its action")
    if not binding_ok:
        reasons.append("acknowledgement is not bound to this case and action")

    # 6. Replay: binding to the record set that already existed when the
    #    acknowledgement was issued. The provider commits to the action's own
    #    events, so the same acknowledgement cannot be lifted into a bundle
    #    whose earlier events differ. The commitment cannot cover this event,
    #    because the root would then depend on the acknowledgement that names it.
    prefix = [e for e in events if e.seq < event.seq]
    prefix_root = (
        build_merkle_tree([leaf_hash(e.canonical_bytes) for e in prefix]).hex()
        if prefix
        else None
    )
    stored_root = _norm_hex(subject.get("batch_root"))
    replay_ok = bool(stored_root) and bool(prefix_root) and stored_root == prefix_root
    if not replay_ok:
        reasons.append(
            "acknowledgement does not commit to the record set of this action (replay possible or unattempted)"
        )

    return CorroborationResult(
        present=True,
        source_party=identity or payload.get("provider"),
        source_type="provider_acknowledgement",
        source_record_id=ref_id if isinstance(ref_id, str) else None,
        source_record_digest=ref_digest if isinstance(ref_digest, str) else None,
        signer_identity=identity,
        signer_identity_verified=identity_ok,
        independent_of_deployment=independent,
        subject_binding_valid=binding_ok,
        provenance_verified=provenance_ok,
        replay_check_passed=replay_ok,
        cryptographic_integrity_valid=crypto_ok,
        reasons=tuple(reasons),
    )


def _legacy_assess_corroboration(
    events: Iterable,
    registry: Optional[KeyRegistry],
    manifest: Optional[BatchManifest],
    policy: Optional[TrustPolicy],
) -> CorroborationResult:
    """Appraise every acknowledgement in the bundle.

    A satisfied acknowledgement corroborates one action, not the case. Every
    action event in the record set therefore needs its own acknowledgement
    before the bundle can carry E3, otherwise a producer could take one authentic
    acknowledgement, append a second action it never obtained confirmation for,
    and present the whole case as corroborated. When any action is uncovered the
    result is not satisfied and names the uncovered actions.
    """
    events = list(events)
    candidates = [e for e in events if e.event_type in PROVIDER_ACK_TYPES]
    if not candidates:
        return CorroborationResult(present=False, reasons=("no provider acknowledgement event",))
    if policy is None:
        return CorroborationResult(
            present=True,
            reasons=("no verifier trust policy was supplied, so no provider identity can be established",),
        )

    collected: List[str] = []
    satisfied = []
    for event in candidates:
        result = _assess_one(event, events, registry, manifest, policy)
        if result.satisfied:
            satisfied.append((event, result))
        else:
            collected.extend(f"{event.event_id}: {r}" for r in result.reasons)

    if not satisfied:
        return CorroborationResult(
            present=True,
            source_type="provider_acknowledgement",
            reasons=tuple(collected),
        )

    covered = set()
    for event, _result in satisfied:
        payload = event.payload if isinstance(event.payload, dict) else {}
        subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
        action_id = subject.get("action_event_id")
        if isinstance(action_id, str):
            covered.add(action_id)

    # Coverage applies to actions that actually proceeded, not to requests the
    # agent declared: a request is a claim about intent and needs no provider.
    action_events = [e for e in events if e.event_type in ACTION_TYPES]
    uncovered = [e for e in action_events if e.event_id not in covered]
    if uncovered:
        best = satisfied[0][1]
        return CorroborationResult(
            present=True,
            source_type="provider_acknowledgement",
            source_record_id=best.source_record_id,
            source_record_digest=best.source_record_digest,
            signer_identity=best.signer_identity,
            signer_identity_verified=best.signer_identity_verified,
            independent_of_deployment=best.independent_of_deployment,
            # Coverage is a binding property: the acknowledgement does not bind
            # to every action in the record set, so binding is not valid.
            subject_binding_valid=False,
            provenance_verified=best.provenance_verified,
            replay_check_passed=best.replay_check_passed,
            cryptographic_integrity_valid=best.cryptographic_integrity_valid,
            reasons=tuple(
                collected
                + [
                    f"{len(uncovered)} action event(s) in this record set have no acknowledgement: "
                    + ", ".join(e.event_id for e in uncovered)
                ]
            ),
        )

    return satisfied[0][1]



def assess_actions(events, registry=None, manifest=None, policy=None):
    """Per-action appraisal: which acknowledgement corroborates which action.

    The case-level call answers "is this record set corroborated". That is the
    wrong question once a case carries two governed actions at different points in
    its history: one action being covered says nothing about the other, and an
    action appended later must not be able to drag a covered one down, nor borrow
    its corroboration.

    Each acknowledgement is appraised against the history that existed when it was
    recorded (the prefix up to its own sequence), because that is the state the
    attestation was written against, including the prior-events root it commits to.
    Returns {action_event_id: (acknowledgement_event, CorroborationResult)}.
    """
    events = list(events)
    ordered = sorted(events, key=lambda event: int(event.seq))
    pairs = {}
    for ack in [event for event in ordered if event.event_type in PROVIDER_ACK_TYPES]:
        payload = ack.payload if isinstance(ack.payload, dict) else {}
        attestation = payload.get("provider_corroboration")
        if not isinstance(attestation, dict):
            attestation = payload.get("corroboration") if isinstance(payload.get("corroboration"), dict) else {}
        action_id = attestation.get("action_event_id")
        if not isinstance(action_id, str) or not action_id:
            subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
            action_id = subject.get("action_event_id")
        if not isinstance(action_id, str) or not action_id:
            continue
        prefix = [event for event in ordered if int(event.seq) <= int(ack.seq)]
        # Independence is judged over the whole record set; coverage over the prefix.
        result = assess_corroboration(prefix, registry, manifest, policy, context_events=events)
        existing = pairs.get(action_id)
        if existing is None or (result.satisfied and not existing[1].satisfied):
            pairs[action_id] = (ack, result)
    return pairs


def assess_corroboration(events, registry=None, manifest=None, policy=None, context_events=None):
    """The canonical appraisal, shared with the engine.

    Imported lazily: `appraisal` imports this module's result class and its
    acknowledgement types, so the dependency runs one way and the public name
    stays here, which is what the verifier and its tests already import.

    `context_events` is forwarded so a caller can appraise a historical prefix
    while judging independence over the whole record.
    """
    from .appraisal import assess_corroboration as _canonical

    return _canonical(
        events,
        registry=registry,
        manifest=manifest,
        policy=policy,
        context_events=context_events,
    )
