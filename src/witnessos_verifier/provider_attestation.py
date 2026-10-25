# WitnessOS Gateway
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""The canonical provider corroboration attestation, and its only appraisal.

One schema, one semantic rule, two transport shapes:

  shape A  a deployment-signed acknowledgement event carrying a provider
           corroboration attestation (the canonical production shape)
  shape B  an acknowledgement event signed by the provider key itself (an
           alternate transport the public verifier already accepted)

Both normalise into the same attestation and are appraised by `verify`. The grade
engine never learns which shape arrived: it is handed verified facts only.

The domain string is part of the signed bytes, so a signature made for this
purpose cannot be replayed as a signature for another.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = "WITNESSOS_PROVIDER_CORROBORATION_V1"

# Methods that authenticate with a key the provider holds. Only these can
# establish independence from the deployment on their own.
SIGNATURE_METHODS = frozenset({"ed25519", "native_signature", "asymmetric_signature"})

# A MAC proves the bytes came from someone who holds the secret. When the
# deployment holds the same secret, that is authentic transport and nothing more:
# the deployment could have manufactured the message. Never independence.
MAC_METHODS = frozenset({"hmac", "hmac_webhook", "mac"})

# Routes where the proof is not a signature at all and an adapter must decide.
DELEGATED_METHODS = frozenset(
    {"api_state_probe", "signed_webhook", "certificate_backed", "external_record"}
)

ACTION_EFFECT_TYPES = frozenset(
    {
        "action.executed",
        "action_executed",
        "action.completed",
        "action_completed",
        "dispatch.started",
        "dispatch.completed",
        "dispatch.blocked",
        "credential.brokered",
        "credential_brokered",
    }
)

REQUIRED_FIELDS = (
    "version",
    "provider_id",
    "acknowledgement_event_id",
    "acknowledgement_type",
    "case_id",
    "action_event_id",
    "action_event_type",
    "outcome",
    "provider_record_id",
    "provider_record_digest",
    "prior_events_root",
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(obj) -> bytes:
    """The one canonical encoding. Keys sorted, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _identity_words(value: str) -> str:
    """Normalised words, the form identities are compared in."""
    return " ".join(str(value).split()).lower()


def signing_bytes(attestation: Mapping) -> bytes:
    """Domain-separated bytes a provider signs: the attestation minus its proof."""
    body = {key: value for key, value in attestation.items() if key != "authentication"}
    auth = attestation.get("authentication") or {}
    if isinstance(auth, Mapping):
        body["authentication"] = {
            key: value for key, value in auth.items() if key not in ("proof", "proof_b64")
        }
    return DOMAIN.encode() + b"\n" + canonical_bytes(body)


@dataclass(frozen=True)
class Facts:
    """What verification established. Only `verify` may build a satisfied one."""

    present: bool = False
    provider_identity_verified: bool = False
    independent_of_deployment: bool = False
    subject_binding_valid: bool = False
    outcome_binding_valid: bool = False
    provenance_verified: bool = False
    replay_check_passed: bool = False
    cryptographic_integrity_valid: bool = False
    # Whether the provider's own retained state substantively supports the
    # claimed outcome. Neutral only where no adapter contract governs the
    # operation; never inferred from the attestation's own claims.
    substantive_valid: bool = False
    provider_identity: Optional[str] = None
    source_record_id: Optional[str] = None
    reasons: tuple = ()
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Producer JSON cannot conjure trusted booleans: a Facts instance is only
        # meaningful when the verifier built it.
        if self._seal is not _VERIFIED:
            raise ValueError("Facts may only be constructed by the verification layer")

    @property
    def satisfied(self) -> bool:
        return bool(
            self.present
            and self.provider_identity_verified
            and self.independent_of_deployment
            and self.subject_binding_valid
            and self.outcome_binding_valid
            and self.provenance_verified
            and self.replay_check_passed
            and self.cryptographic_integrity_valid
            # Substantive agreement with the provider's own state is part of
            # being satisfied, not a separate opinion a caller may ignore.
            and self.substantive_valid
        )


_VERIFIED = object()


def _facts(**kwargs) -> Facts:
    kwargs["_seal"] = _VERIFIED
    return Facts(**kwargs)


def normalise(payload: Mapping, ack: Mapping) -> tuple:
    """Return (attestation, shape) from an acknowledgement payload.

    Accepts the canonical key, the previous block key, and a provider-signed
    envelope. Returns (None, None) when the acknowledgement carries neither.
    """
    raw = payload.get("provider_corroboration")
    if isinstance(raw, Mapping):
        return _from_block(raw, ack), "canonical"
    legacy = payload.get("provider_authentication")
    if isinstance(legacy, Mapping):
        return _from_legacy(legacy, ack), "legacy-block"
    signed = ack.get("signed")
    if isinstance(signed, Mapping) and (signed.get("signer_key_id") or signed.get("key_id")):
        return _from_signed_event(ack), "provider-signed-event"
    return None, None


def _from_block(block: Mapping, ack: Mapping) -> dict:
    att = dict(block)
    att.setdefault("acknowledgement_event_id", ack.get("event_id"))
    att.setdefault("acknowledgement_type", ack.get("event_type"))
    att.setdefault("case_id", ack.get("case_id"))
    att.setdefault("version", DOMAIN)
    auth = dict(att.get("authentication") or {})
    if "method" not in auth and block.get("scheme"):
        auth["method"] = "ed25519" if block.get("scheme") == "ed25519" else str(block.get("scheme"))
    if "key_id" not in auth and block.get("public_key_hex"):
        auth["key_id"] = block.get("public_key_hex")
    if "proof" not in auth and block.get("signature_b64"):
        auth["proof"] = block.get("signature_b64")
    att["authentication"] = auth
    return att


def _from_legacy(block: Mapping, ack: Mapping) -> dict:
    """The pre-canonical block: same semantics, older field placement."""
    payload = ack.get("payload") if isinstance(ack.get("payload"), Mapping) else {}
    att = {
        "version": DOMAIN,
        "provider_id": block.get("provider") or payload.get("provider"),
        "acknowledgement_event_id": block.get("ack_event_id") or ack.get("event_id"),
        "acknowledgement_type": block.get("ack_event_type") or ack.get("event_type"),
        "case_id": block.get("case_id") or ack.get("case_id"),
        "action_event_id": block.get("action_event_id"),
        "action_event_type": block.get("action_event_type"),
        "outcome": block.get("outcome"),
        "provider_record_id": block.get("provider_record_id"),
        "provider_record_digest": block.get("provider_record_digest"),
        "prior_events_root": block.get("replay_root") or block.get("prior_events_root"),
        "authentication": {
            "method": block.get("scheme") or "ed25519",
            "key_id": block.get("public_key_hex"),
            "proof": block.get("signature_b64") or block.get("proof"),
        },
    }
    return att


def _from_signed_event(ack: Mapping) -> dict:
    """A provider-signed envelope, expressed as the canonical attestation."""
    payload = ack.get("payload") if isinstance(ack.get("payload"), Mapping) else {}
    signed = ack.get("signed") if isinstance(ack.get("signed"), Mapping) else {}
    subject = payload.get("subject") if isinstance(payload.get("subject"), Mapping) else {}
    outcome = payload.get("outcome") or payload.get("status") or ""
    attestation = {
        "version": DOMAIN,
        "provider_id": payload.get("provider"),
        "acknowledgement_event_id": ack.get("event_id"),
        "acknowledgement_type": ack.get("event_type"),
        "case_id": subject.get("case_id") or ack.get("case_id"),
        "action_event_id": subject.get("action_event_id"),
        "action_event_type": payload.get("action_event_type") or payload.get("action_type") or "",
        "outcome": outcome,
        "provider_record_id": payload.get("provider_record_id"),
        "provider_record_digest": payload.get("provider_record_digest"),
        "prior_events_root": payload.get("prior_events_root")
        or subject.get("prior_events_root")
        or subject.get("batch_root")
        or signed.get("prior_events_root"),
        "authentication": {
            "method": "provider_signed_event",
            "key_id": signed.get("signer_key_id") or signed.get("key_id") or ack.get("signer"),
            "proof": ack.get("signature") or signed.get("signature"),
        },
    }
    puts_unstated = not outcome  # recorded for the reader, grants nothing
    if puts_unstated:
        attestation["outcome_unstated"] = True
    return attestation


@dataclass
class Context:
    """Everything the appraisal needs that is not the attestation itself."""

    ack: Mapping
    events: Sequence
    provider_keys: Mapping          # public key hex -> provider identity
    deployment_key_ids: set
    deployment_key_hexes: set
    expected_root: Optional[str]
    deployment_known: bool = True
    authenticator: Optional[Callable] = None   # adapter route for delegated methods
    envelope_verifier: Optional[Callable] = None  # shape B: verifies the event signature
    provider_records: Mapping = field(default_factory=dict)  # frozen provider objects by id
    # One provider object cannot substantiate two actions. Shared across the
    # acks of a single appraisal, so the first claim keeps it and the rest fail.
    record_usage: dict = field(default_factory=dict)


def _action_facts(action) -> dict:
    """The facts of an action event, in either representation.

    The engine's canonical action.executed carries the effect's facts under
    `effect`, while a hand-built description may state them flat. Reading one
    shape only made an engine-issued receipt unable to satisfy a provider's
    substantive contract. Where both name a key the effect wins: the event's own
    `outcome` field is the deployment's word, the effect states what happened.
    """
    if not (isinstance(action, Mapping) and isinstance(action.get("payload"), Mapping)):
        return {}
    facts = dict(action["payload"])
    nested = facts.get("effect")
    if isinstance(nested, Mapping):
        facts = {**facts, **nested}
    return facts


def verify(attestation: Mapping, ctx: Context) -> Facts:
    """Appraise an attestation. The only place a satisfied Facts is produced."""
    reasons: list = []
    att = dict(attestation or {})
    auth = att.get("authentication") if isinstance(att.get("authentication"), Mapping) else {}
    method = str(auth.get("method") or "").lower()

    # A provider-signed envelope states the action by reference. Its type is
    # inside the signed envelope, so reading it from the referenced event is
    # reading the evidence, not accepting a claim about it.
    transport_signed = method == "provider_signed_event" or bool(att.get("transport_omits_outcome"))
    if transport_signed and not str(att.get("action_event_type") or "").strip():
        referenced = next(
            (e for e in ctx.events if str(e.get("event_id")) == str(att.get("action_event_id"))),
            None,
        )
        if referenced is not None:
            att["action_event_type"] = str(referenced.get("event_type") or "")

    missing = [name for name in REQUIRED_FIELDS if not str(att.get(name) or "").strip()]
    complete = not missing
    if missing:
        reasons.append(f"attestation does not state {', '.join(missing)}")

    ack = ctx.ack
    ack_ok = bool(
        complete
        and str(att.get("acknowledgement_event_id")) == str(ack.get("event_id"))
        and str(att.get("acknowledgement_type")) == str(ack.get("event_type"))
        and str(att.get("case_id")) == str(ack.get("case_id"))
    )
    if complete and not ack_ok:
        reasons.append("attestation names a different acknowledgement, type or case")

    action_id = str(att.get("action_event_id") or "")
    action = next((e for e in ctx.events if str(e.get("event_id")) == action_id), None)
    subject_ok = False
    if action is None:
        reasons.append("attestation names an action event that is not in this record")
    elif str(action.get("event_type")) not in ACTION_EFFECT_TYPES:
        reasons.append(
            f"attestation names {action.get('event_type')}, which is not an action or effect event"
        )
    elif str(action.get("case_id")) != str(ack.get("case_id")):
        reasons.append("attestation names an action event from another case")
    elif int(action.get("seq", 0)) >= int(ack.get("seq", 0)):
        reasons.append("attestation does not precede the acknowledgement")
    elif str(att.get("action_event_type")) != str(action.get("event_type")):
        reasons.append("attestation names a different action type from the event it references")
    else:
        subject_ok = True

    payload = ack.get("payload") if isinstance(ack.get("payload"), Mapping) else {}
    # The outcome the record states is the outcome of the action being
    # corroborated, so read it from that action event. The acknowledgement's own
    # payload is only a fallback for transports that restate it there.
    action_event = next(
        (e for e in ctx.events if str(e.get("event_id")) == str(att.get("action_event_id"))),
        None,
    )
    action_payload = _action_facts(action_event)
    recorded_outcome = str(
        action_payload.get("outcome")
        or action_payload.get("status")
        or payload.get("outcome")
        or payload.get("status")
        or ""
    )
    declared_outcome = str(att.get("outcome") or "").strip()
    # The provider must have authenticated the outcome. Where the transport does
    # not cover an outcome, the provider has corroborated a record, not a result,
    # and E3 is not satisfied. Nothing here infers an outcome from the record.
    outcome_ok = bool(declared_outcome) and (
        not recorded_outcome or recorded_outcome == declared_outcome
    )
    if not outcome_ok:
        reasons.append("attestation does not bind the outcome the record states")

    record_id = str(att.get("provider_record_id") or "")
    digest = str(att.get("provider_record_digest") or "").lower()
    provenance_ok = bool(record_id) and record_id not in (
        str(ack.get("event_id")),
        str(ack.get("case_id")),
    ) and bool(_HEX64.match(digest))
    if not provenance_ok:
        reasons.append("attestation names no external record of its own (id and 64-hex digest)")

    root_ok = bool(ctx.expected_root) and str(att.get("prior_events_root") or "") == str(ctx.expected_root)
    if not root_ok:
        reasons.append("attestation does not commit to this case's prior events")

    # Authentication, and with it identity and independence.
    identity = None
    integrity = False
    independent = False
    key_id = str(auth.get("key_id") or auth.get("trust_reference") or "")
    proof = auth.get("proof") or auth.get("proof_b64")

    if method in SIGNATURE_METHODS:
        key_hex = key_id.lower()
        identity = ctx.provider_keys.get(key_hex)
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
            key.verify(base64.b64decode(str(proof or ""), validate=True), signing_bytes(att))
            integrity = True
        except (InvalidSignature, ValueError, TypeError):
            integrity = False
            reasons.append("provider signature does not verify over the attestation")
        independent = bool(identity) and key_hex not in ctx.deployment_key_hexes and (
            not key_id or key_id not in ctx.deployment_key_ids
        )
        claimed = str(att.get("provider_id") or "").strip()
        if identity and claimed and _identity_words(identity) != _identity_words(claimed):
            # The block may name any provider. The key must be provisioned to
            # that name, so a signature cannot retroactively supply an identity.
            identity = None
        if not identity:
            reasons.append("provider key is not provisioned, so no identity is established")
        elif not independent:
            reasons.append("attestation was signed by a key the deployment also uses")
    elif method == "provider_signed_event":
        # Shape B: the proof is the event signature over the whole envelope, and
        # the key is resolved by the caller's envelope verifier.
        if ctx.envelope_verifier is None:
            reasons.append("no envelope verifier was supplied for a provider-signed event")
        else:
            ok, key_hex = ctx.envelope_verifier(ack, key_id, att.get("provider_id"))
            integrity = bool(ok)
            identity = ctx.provider_keys.get(str(key_hex or "").lower()) if key_hex else None
            independent = bool(identity) and str(key_hex).lower() not in ctx.deployment_key_hexes
            if not ok:
                reasons.append("provider signature over the acknowledgement event does not verify")
            elif not identity:
                reasons.append("provider key is not provisioned, so no identity is established")
            elif not independent:
                reasons.append("event was signed by a key the deployment also uses")
    elif method in MAC_METHODS:
        # Authentic transport only. The deployment may hold the same secret, so
        # possession of a valid MAC is not independent corroboration.
        integrity = bool(proof) and ctx.authenticator is not None and bool(
            ctx.authenticator(att)
        )
        independent = False
        identity = None
        reasons.append(
            "MAC-authenticated evidence proves transport, not independence: the deployment may "
            "hold the same secret, so an out-of-band provider probe is required"
        )
    elif method in DELEGATED_METHODS:
        result = ctx.authenticator(att) if ctx.authenticator is not None else None
        if isinstance(result, Mapping) and result.get("ok"):
            integrity = True
            identity = result.get("provider_identity")
            independent = bool(result.get("independent"))
            if not independent:
                reasons.append("adapter did not establish independence for this method")
        else:
            reasons.append(f"no adapter established {method} evidence for this attestation")
    else:
        reasons.append(f"authentication method {method or '(absent)'} cannot be appraised")

    identity_verified = bool(identity)
    if not identity_verified and method not in MAC_METHODS:
        reasons.append("no provisioned provider identity was established")

    if not ctx.deployment_known:
        # An unreadable deployment registry is not an empty one: every provider
        # key would look independent, which fails open.
        independent = False
        reasons.append(
            "the deployment's own key registry could not be read, so independence "
            "of the provider key cannot be established"
        )

    # Identity is not substance. Where an adapter contract governs this operation,
    # the retained provider object must agree with the action and the claimed
    # outcome, and every disagreement caps the grade below E3 with its own code.
    substantive_ok, substantive_reasons = substantive_check(
        att,
        action,
        ctx.provider_records,
        ack_id=str(ack.get("event_id")),
        usage=ctx.record_usage,
    )
    reasons.extend(substantive_reasons)

    return _facts(
        present=True,
        substantive_valid=bool(substantive_ok),
        provider_identity_verified=identity_verified,
        independent_of_deployment=bool(independent),
        subject_binding_valid=bool(subject_ok and ack_ok),
        outcome_binding_valid=bool(outcome_ok),
        provenance_verified=bool(provenance_ok),
        replay_check_passed=bool(root_ok),
        cryptographic_integrity_valid=bool(integrity),
        provider_identity=identity,
        source_record_id=record_id or None,
        reasons=() if (
            identity_verified
            and independent
            and subject_ok
            and outcome_ok
            and provenance_ok
            and root_ok
            and integrity
            and ack_ok
            and substantive_ok
        ) else tuple(dict.fromkeys(reasons)),
    )


def digest_of_record(record: bytes) -> str:
    return hashlib.sha256(record).hexdigest()


# ─── Substantive provider corroboration ─────────────────────────────────────
# Authentication answers "did this come from the provider". It does not answer
# "does the provider's own retained state support the outcome claimed for this
# governed action". Adapter contracts live here so the grade engine carries no
# vendor rules, and so every implementation reads the same one.

PROVIDER_RECORDS_ENV = "WITNESSOS_PROVIDER_RECORDS_DIR"

SUBSTANTIVE_CONTRACTS = {
    "stripe.refund.create": {
        "provider": "Stripe",
        "object": "refund",
        "subject_fields": ("payment_intent", "charge"),
        # Stripe's own refund status, and the WitnessOS outcome each substantiates.
        "outcomes": {
            "succeeded": frozenset({"succeeded"}),
            "failed": frozenset({"failed", "canceled"}),
            "pending": frozenset({"pending", "requires_action"}),
        },
    },
}


def provider_record_digest(record) -> str:
    """The one digest rule: canonical JSON bytes, SHA-256, bare 64-hex.

    Canonical means keys sorted, no whitespace, UTF-8, which is the same
    encoding the attestation itself is signed over. A record read back from disk
    produces the same digest regardless of how its producer formatted it.
    """
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def load_provider_records(directory=None) -> dict:
    """Frozen provider objects, keyed by the provider's own object id.

    Verification must not need the provider to stay reachable, so the record an
    attestation refers to travels with the evidence and is hashed on read.
    """
    base = directory or os.environ.get(PROVIDER_RECORDS_ENV)
    records: dict = {}
    if not base:
        return records
    path = Path(base)
    if not path.is_dir():
        return records
    for entry in sorted(path.glob("*.json")):
        try:
            record = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, Mapping) and str(record.get("id") or "").strip():
            records[str(record["id"])] = record
    return records


def substantive_check(
    attestation: Mapping,
    action: Optional[Mapping],
    records: Mapping,
    ack_id: Optional[str] = None,
    usage: Optional[dict] = None,
) -> tuple:
    """(ok, reasons) — vendor state must support the exact claimed outcome.

    Returns (True, ()) only when no adapter contract governs this operation, or
    when the retained provider object substantively agrees with the action and
    the claimed outcome. Every failure carries a stable reason code so an auditor
    can tell "wrong amount" from "provider never issued this record".
    """
    action_payload = _action_facts(action)
    action_type = str(action_payload.get("action_type") or "").strip()
    contract = SUBSTANTIVE_CONTRACTS.get(action_type)
    if contract is None:
        if action_type.lower().startswith(f"{str(attestation.get('provider_id') or '').strip().lower()}."):
            return False, (f"provider_operation_unsupported: no contract for {action_type}",)
        if action_type.lower().startswith("stripe."):
            return False, (f"provider_operation_unsupported: no contract for {action_type}",)
        # No adapter governs this operation, so there is no vendor rule to apply.
        # A retained provider record is still evidence: where the record travels
        # with the bundle it must be the object the attestation signed, and one
        # record substantiates one action. Absent a retained record there is
        # nothing to contradict, so the generic claim stands unexamined rather
        # than being failed for a shape it never promised.
        generic_id = str(attestation.get("provider_record_id") or "").strip()
        generic_record = records.get(generic_id) if isinstance(records, Mapping) and generic_id else None
        if isinstance(generic_record, Mapping):
            if provider_record_digest(generic_record) != str(
                attestation.get("provider_record_digest") or ""
            ).strip().lower():
                return False, (
                    "provider_record_digest_mismatch: retained object does not hash to the "
                    "attested digest",
                )
            if usage is not None:
                first = usage.get(generic_id)
                if first is not None and str(first) != str(ack_id):
                    return False, (
                        f"provider_record_reused: {generic_id} already substantiated {first}",
                    )
                usage[generic_id] = ack_id
        return True, ()

    claimed = str(attestation.get("outcome") or "").strip().lower()
    record_id = str(attestation.get("provider_record_id") or "").strip()
    digest = str(attestation.get("provider_record_digest") or "").strip().lower()

    record = records.get(record_id) if isinstance(records, Mapping) else None
    if not isinstance(record, Mapping):
        return False, (f"provider_record_not_found: {record_id} is not retained with the evidence",)
    if str(record.get("id") or "") != record_id:
        return False, (
            f"provider_record_id_mismatch: retained object is {record.get('id')}, "
            f"attestation names {record_id}",
        )
    if provider_record_digest(record) != digest:
        return False, (
            "provider_record_digest_mismatch: retained object does not hash to the "
            "attested digest",
        )
    if usage is not None and record_id:
        # Authentic and unrelated is not corroboration, and neither is authentic
        # and reused: one provider object substantiates one governed action.
        first = usage.get(record_id)
        if first is not None and str(first) != str(ack_id):
            return False, (
                f"provider_record_replayed: {record_id} already substantiates "
                f"acknowledgement {first}",
            )
        usage[record_id] = ack_id
    if str(record.get("object") or "").strip().lower() != contract["object"]:
        return False, (
            f"provider_object_type_mismatch: {record.get('object')} is not a "
            f"{contract['object']}",
        )

    target = str(action_payload.get("target_id") or "").strip()
    if target:
        related = {
            str(record.get(field) or "").strip()
            for field in contract["subject_fields"]
            if record.get(field)
        }
        if target not in related:
            return False, (
                f"provider_subject_mismatch: object belongs to "
                f"{sorted(related) or 'no known subject'}, action targets {target}",
            )
    else:
        return False, ("provider_subject_mismatch: action names no provider object to bind",)

    if action_payload.get("amount") is not None:
        try:
            if int(record.get("amount")) != int(action_payload["amount"]):
                return False, (
                    f"provider_amount_mismatch: provider {record.get('amount')} "
                    f"!= action {action_payload['amount']}",
                )
        except (TypeError, ValueError):
            return False, ("provider_amount_mismatch: amount is not an integer in minor units",)
    else:
        return False, ("provider_amount_mismatch: action states no amount to compare",)

    if action_payload.get("currency") is not None:
        if str(record.get("currency") or "").strip().lower() != str(
            action_payload["currency"]
        ).strip().lower():
            return False, (
                f"provider_currency_mismatch: provider {record.get('currency')} "
                f"!= action {action_payload['currency']}",
            )
    else:
        return False, ("provider_currency_mismatch: action states no currency to compare",)

    allowed = contract["outcomes"].get(claimed)
    if allowed is None:
        return False, (f"provider_outcome_unsupported: no provider mapping for {claimed or '(absent)'}",)
    status = str(record.get("status") or "").strip().lower()
    known = {state for states in contract["outcomes"].values() for state in states}
    if status not in known:
        return False, (f"provider_status_unsupported: {status or '(absent)'} is not a known provider state",)
    if status not in allowed:
        return False, (
            f"provider_outcome_mismatch: provider state {status} contradicts claimed {claimed}",
        )

    created = record.get("created")
    action_created = action_payload.get("created_at")
    if isinstance(created, int) and isinstance(action_created, int):
        if created < action_created:
            return False, (
                f"provider_temporal_mismatch: provider object predates the action "
                f"({created} < {action_created})",
            )
    return True, ()
