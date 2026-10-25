"""Ordering of a governed action's evidence, proved from the artefact alone.

The issuer refuses provider evidence whose times precede the dispatch. That is a
boundary check, and a relying party cannot inherit it: the artefact has to carry
enough to re-derive the same conclusion without the issuer in the room.

So this module reads only what the bundle states, compares instants rather than
strings, and fails closed. An absent time, an unreadable time or a time with no
offset (which is a wall clock reading, not an instant) is a failure, not a pass
by omission.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# An instant states its own offset. Without one there is no instant, only a
# reading whose zone lives outside the evidence.
_OFFSET = re.compile(r"(?:[Zz]|[+-]\d{2}:?\d{2})$")

COMPLETION_STATES = frozenset(
    {"completed", "complete", "succeeded", "success", "done", "finished", "ok"}
)


def instant(value: object) -> datetime | None:
    """The UTC instant a timestamp denotes, or None when it denotes none.

    None means unreadable, in the fail-closed sense: naive local time, a bad
    shape, a missing value and a non-string all land here.
    """
    text = str(value or "").strip()
    if not text or not _OFFSET.search(text):
        return None
    normalised = text.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def check(
    *,
    dispatch_at: object,
    effect_started_at: object,
    effect_finished_at: object,
    asserted_at: object,
    completion_state: object = "",
    required: bool = True,
) -> tuple[bool, tuple[str, ...], dict]:
    """Decide whether the evidence's own times are possible.

    `required` is true for evidence that declares a binding version requiring the
    full time set (governed-action-binding/v2 and later). Evidence issued before
    that contract may legitimately omit the effect's own times, so it is judged
    on whatever times it does state, and a stated time still has to be readable.
    """
    stated = {
        "dispatch": dispatch_at,
        "effect.started_at": effect_started_at,
        "effect.finished_at": effect_finished_at,
        "attestation.asserted_at": asserted_at,
    }
    parsed = {name: instant(raw) for name, raw in stated.items()}
    reasons: list[str] = []

    for name, raw in stated.items():
        present = bool(str(raw or "").strip())
        if parsed[name] is not None:
            continue
        if present:
            reasons.append(f"ordering: {name} {raw!r} is not an instant with an offset")
        elif required:
            reasons.append(f"ordering: the evidence states no {name}")

    dispatch = parsed["dispatch"]
    started = parsed["effect.started_at"]
    finished = parsed["effect.finished_at"]
    asserted = parsed["attestation.asserted_at"]

    if dispatch and started and started < dispatch:
        reasons.append(
            "ordering: the effect starts before the governed dispatch "
            f"({iso(started)} < {iso(dispatch)})"
        )
    if started and finished and finished < started:
        reasons.append(
            "ordering: the effect finishes before it starts "
            f"({iso(finished)} < {iso(started)})"
        )
    if dispatch and asserted and asserted < dispatch:
        reasons.append(
            "ordering: the attestation predates the governed dispatch "
            f"({iso(asserted)} < {iso(dispatch)})"
        )
    # A provider that says the action completed cannot have signed that statement
    # before the action completed.
    state = str(completion_state or "").strip().lower()
    if state in COMPLETION_STATES and finished and asserted and asserted < finished:
        reasons.append(
            "ordering: the attestation declares completion before the effect finished "
            f"({iso(asserted)} < {iso(finished)})"
        )

    facts = {
        "ordering_checked": True,
        "ordering_required": bool(required),
        "ordering_valid": not reasons,
        "ordering_dispatch_at": iso(dispatch),
        "ordering_effect_started_at": iso(started),
        "ordering_effect_finished_at": iso(finished),
        "ordering_asserted_at": iso(asserted),
        "ordering_reasons": tuple(reasons),
    }
    return (not reasons), tuple(reasons), facts
