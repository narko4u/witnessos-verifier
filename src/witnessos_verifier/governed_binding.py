"""The governed action binding, version 2, implemented from the published rule.

v1.0.2 binds a case to the digest of the mission content (intent, steps,
capability profile, robot class). Two identically worded missions therefore
produce one digest, and the content cannot tell you which of them ran. v2 adds
the governed action's external identity to the signed binding, and it does so as
a version rather than an edit, so v1 evidence keeps verifying under v1.

The rule, stated so another implementation can reproduce it:

    binding_version  "governed-action-binding/v2"
    fields           binding_version, case_id, external_action_id,
                     action_digest, action_type, target
    serializer       JSON, sort_keys, separators ("," ":"), ensure_ascii, UTF-8
    hash             SHA-256
    prefix           "sha256:"

`external_action_id` is the relying party's name for the action, whatever its
domain calls it. Atlas maps its mission id onto it. Nothing here is specific to
robots.
"""

from __future__ import annotations

import hashlib
import json

BINDING_VERSION = "governed-action-binding/v2"
FIELDS = (
    "binding_version",
    "case_id",
    "external_action_id",
    "action_digest",
    "action_type",
    "target",
)


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def digest(
    *,
    case_id: str,
    external_action_id: str,
    action_digest: str,
    action_type: str,
    target: str,
) -> str:
    body = {
        "binding_version": BINDING_VERSION,
        "case_id": str(case_id),
        "external_action_id": str(external_action_id),
        "action_digest": str(action_digest),
        "action_type": str(action_type),
        "target": str(target),
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def declares_v2(*values: object) -> bool:
    """Whether any supplied version marker asks for v2 or later."""
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            continue
        if text == BINDING_VERSION:
            return True
        tail = text.rsplit("/v", 1)
        if len(tail) == 2 and tail[1].isdigit() and int(tail[1]) >= 2:
            return True
    return False


def check(
    *,
    case_id: object,
    declared_version: object,
    stored_binding: object,
    attested_binding: object,
    case_external_action_id: object,
    effect_external_action_id: object,
    attested_external_action_id: object,
    action_digest: object,
    action_type: object,
    target: object,
    required: bool,
) -> tuple[bool, tuple[str, ...], dict]:
    """Decide whether this evidence names the same governed action the case does.

    Every comparison is against a value the case already recorded, so a party
    cannot introduce identity with the attestation it is signing.
    """
    reasons: list[str] = []
    version = str(declared_version or "").strip()
    case_external = str(case_external_action_id or "").strip()

    if required and not version:
        reasons.append(f"binding: the evidence declares no binding version, v2 is required")
    if required and not case_external:
        reasons.append("binding: the case records no external action identity")

    for name, value in (
        ("the effect", effect_external_action_id),
        ("the attestation", attested_external_action_id),
    ):
        if not str(value or "").strip():
            if required:
                reasons.append(f"binding: {name} states no external action identity")
            continue
        if case_external and str(value).strip() != case_external:
            reasons.append(
                f"binding: {name} names external action {value!r}, but this case governs "
                f"{case_external!r}"
            )

    recomputed = ""
    if case_external and str(action_digest or "").strip():
        recomputed = digest(
            case_id=str(case_id),
            external_action_id=case_external,
            action_digest=str(action_digest),
            action_type=str(action_type or ""),
            target=str(target or ""),
        )
        stored = str(stored_binding or "").strip()
        if required and not stored:
            reasons.append("binding: the case records no v2 binding digest")
        if stored and stored != recomputed:
            reasons.append(
                "binding: the case's recorded binding does not recompute from its own fields"
            )
        attested = str(attested_binding or "").strip()
        if required and not attested:
            reasons.append("binding: the attestation binds no governed action digest")
        if attested and attested != recomputed:
            reasons.append(
                "binding: the attestation binds a different governed action than this case"
            )

    facts = {
        "binding_checked": True,
        "binding_required": bool(required),
        "binding_version": version or None,
        "binding_external_action_id": case_external or None,
        "binding_recomputed": recomputed or None,
        "binding_valid": not reasons,
        "binding_reasons": tuple(reasons),
    }
    return (not reasons), tuple(reasons), facts
