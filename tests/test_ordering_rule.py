# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0

"""The relying party's own ordering rule.

The Gateway refuses provider evidence whose times precede the dispatch it
recorded. That is the issuer checking itself, and a relying party holds only the
bundle, so the same invariant has to be derivable from the artefact. These tests
fix the rule at the level a verifier can rely on: instants, not strings, and a
refusal rather than a pass by omission when a time cannot be read.
"""

from __future__ import annotations

from datetime import datetime, timezone

from witnessos_verifier.ordering import check, instant


def test_an_instant_needs_an_offset():
    assert instant("2026-10-25T13:38:02Z") == datetime(2026, 10, 25, 13, 38, 2, tzinfo=timezone.utc)
    assert instant("2026-10-25T13:38:02+00:00") is not None
    assert instant("2026-10-25T23:38:02+10:00") == instant("2026-10-25T13:38:02Z")


def test_a_wall_clock_reading_is_not_an_instant():
    # The same text with no zone could mean any of 24 hours, so it is refused
    # rather than assumed to be UTC.
    assert instant("2026-10-25 13:38:02") is None
    assert instant("2026-10-25T13:38:02") is None
    assert instant("not a time") is None
    assert instant(None) is None
    assert instant("") is None


def _call(**overrides):
    base = {
        "dispatch_at": "2026-10-25T13:00:00Z",
        "effect_started_at": "2026-10-25T13:00:05Z",
        "effect_finished_at": "2026-10-25T13:00:09Z",
        "asserted_at": "2026-10-25T13:00:10Z",
        "completion_state": "completed",
        "required": True,
    }
    base.update(overrides)
    return check(**base)


def test_honest_ordering_passes():
    ok, reasons, facts = _call()
    assert ok, reasons
    assert facts["ordering_valid"] is True
    assert facts["ordering_dispatch_at"] == "2026-10-25T13:00:00.000Z"
    assert facts["ordering_effect_finished_at"] == "2026-10-25T13:00:09.000Z"


def test_an_effect_that_starts_before_the_dispatch_is_refused():
    ok, reasons, _ = _call(effect_started_at="2026-10-25T12:59:55Z")
    assert not ok
    assert any("starts before the governed dispatch" in r for r in reasons)


def test_an_effect_that_finishes_before_it_starts_is_refused():
    ok, reasons, _ = _call(effect_finished_at="2026-10-25T13:00:01Z")
    assert not ok
    assert any("finishes before it starts" in r for r in reasons)


def test_an_attestation_that_predates_the_dispatch_is_refused():
    ok, reasons, _ = _call(asserted_at="2026-10-25T12:59:00Z")
    assert not ok
    assert any("predates the governed dispatch" in r for r in reasons)


def test_completion_cannot_be_declared_before_the_effect_finished():
    ok, reasons, _ = _call(asserted_at="2026-10-25T13:00:06Z", completion_state="completed")
    assert not ok
    assert any("declares completion before the effect finished" in r for r in reasons)


def test_offsets_compare_as_instants_not_strings():
    # 23:00+10:00 is 13:00Z. Lexically the started_at string sorts before the
    # dispatch string; as instants it is safely after it.
    ok, reasons, _ = _call(
        dispatch_at="2026-10-25T13:00:00Z",
        effect_started_at="2026-10-25T23:00:05+10:00",
        effect_finished_at="2026-10-25T23:00:09+10:00",
        asserted_at="2026-10-25T23:00:10+10:00",
    )
    assert ok, reasons


def test_a_missing_time_fails_closed_when_the_binding_requires_it():
    ok, reasons, _ = _call(asserted_at="")
    assert not ok
    assert any("states no attestation.asserted_at" in r for r in reasons)


def test_evidence_older_than_the_binding_is_judged_on_the_times_it_states():
    # Pre-v2 evidence legitimately carries no effect times. What it does state
    # still has to be readable and in order.
    ok, reasons, _ = check(
        dispatch_at="2026-10-25T13:00:00Z",
        effect_started_at=None,
        effect_finished_at=None,
        asserted_at="2026-10-25T13:00:10Z",
        completion_state="",
        required=False,
    )
    assert ok, reasons


def test_a_malformed_time_is_refused_even_when_not_required():
    ok, reasons, _ = check(
        dispatch_at="2026-10-25T13:00:00Z",
        effect_started_at=None,
        effect_finished_at=None,
        asserted_at="2026-10-25 13:00:10",
        completion_state="",
        required=False,
    )
    assert not ok
    assert any("not an instant with an offset" in r for r in reasons)
