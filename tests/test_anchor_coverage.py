"""Anchor coverage: the properties that make a checkpoint mean something.

These tests hold the coverage model to the invariants it exists for. A coverage
record is not a claim about what an anchor covers, it is a claim that is checked:
the ids must match the range, the range must match the events, the events must
reproduce the committed root, and the token must authenticate that root on an
accepted trust path without preceding it.

The token verifier is stubbed here so the ordering and membership logic is tested
without a network call. The real token path is exercised end to end by the
conformance matrix, which uses a genuine third-party anchor.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from witnessos_verifier import anchor_coverage
from witnessos_verifier.anchor_coverage import (
    load_records,
    qualifying_chain,
    verify_coverage,
)
from witnessos_verifier.events import Event
from witnessos_verifier.grades import Grade, derive_action_grades
from witnessos_verifier.merkle import build_merkle_tree, leaf_hash


def _event(seq: int, event_type: str, event_id: str, payload=None) -> Event:
    raw = f'{{"case_id":"case_1","event_id":"{event_id}","event_type":"{event_type}","seq":{seq}}}'.encode()
    return Event(
        event_id=event_id,
        event_type=event_type,
        case_id="case_1",
        seq=seq,
        prev_hash="",
        payload=payload or {},
        raw=raw,
    )


def _root(events) -> str:
    leaves = [leaf_hash(event.canonical_bytes) for event in sorted(events, key=lambda e: e.seq)]
    return build_merkle_tree(leaves).hex()


@dataclass
class _StubTimestamp:
    valid: bool = True
    imprint_matches: bool = True
    signature_verified: bool = True
    trust_verified: bool = True
    gen_time: str = "2026-10-21T12:00:00+00:00"

    @property
    def tst_info(self):
        return type("Info", (), {"gen_time": self.gen_time})()


@pytest.fixture()
def bundle(tmp_path, monkeypatch):
    directory = tmp_path / "bundle"
    (directory / "anchor").mkdir(parents=True)
    (directory / "timestamp").mkdir()
    (directory / "anchor" / "ac-1.tsr").write_bytes(b"token")
    monkeypatch.setattr(
        anchor_coverage, "verify_timestamp", lambda *a, **k: _StubTimestamp()
    )
    return directory


def _events():
    return [
        _event(0, "observation.recorded", "evt_obs"),
        _event(1, "policy.evaluated", "evt_policy"),
        _event(2, "dispatch.started", "evt_dispatch"),
        _event(3, "action.executed", "evt_action_a"),
        _event(4, "provider.confirmed", "evt_ack_a"),
        _event(5, "action.executed", "evt_action_b"),
        _event(6, "provider.confirmed", "evt_ack_b"),
    ]


def _record(events, first, last, **overrides):
    covered = [event for event in events if first <= event.seq <= last]
    record = {
        "anchor_coverage_version": 1,
        "checkpoint_id": overrides.pop("checkpoint_id", "chk_1"),
        "case_id": "case_1",
        "batch_id": "batch_1",
        "first_seq": first,
        "last_seq": last,
        "covered_event_ids": [event.event_id for event in covered],
        "covered_root": _root(covered),
        "finalised_at": "2026-10-21T09:00:00Z",
        "tsa": {
            "token_file": "anchor/ac-1.tsr",
            "imprint": hashlib.sha256(bytes.fromhex(_root(covered))).hexdigest(),
            "trust_reference": "tsa-root.pem",
        },
    }
    record.update(overrides)
    return record


def _parsed(record):
    return anchor_coverage._parse_record(record, source="ac-1.json")


def test_coverage_authenticates_when_every_fact_agrees(bundle):
    events = _events()
    result = verify_coverage(_parsed(_record(events, 0, 4)), events, bundle, manifest_case_id="case_1")
    assert result.errors == []
    assert result.authenticated is True
    assert result.anchored_ids == {"evt_obs", "evt_policy", "evt_dispatch", "evt_action_a", "evt_ack_a"}


def test_modified_event_list_does_not_reproduce_the_root(bundle):
    """AC-06. Editing the covered list without reproducing the anchored root fails."""
    events = _events()
    record = _record(events, 0, 4)
    record["covered_event_ids"] = record["covered_event_ids"] + ["evt_action_b"]
    record["last_seq"] = 5
    result = verify_coverage(_parsed(record), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False
    # The list and the range now agree, which is exactly why the root has to be
    # recomputed: agreement between two pieces of metadata proves nothing.
    assert any("do not reproduce the committed root" in error for error in result.errors)


def test_missing_event_inside_the_declared_range_fails(bundle):
    """AC-01. A range that claims events the record does not list is not coverage."""
    events = _events()
    record = _record(events, 0, 4)
    record["covered_event_ids"] = [i for i in record["covered_event_ids"] if i != "evt_policy"]
    result = verify_coverage(_parsed(record), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False
    assert any("disagree" in error for error in result.errors)


def test_event_outside_the_declared_range_fails(bundle):
    """AC-02. An id claimed as covered whose sequence sits outside the range fails."""
    events = _events()
    record = _record(events, 0, 3)
    record["covered_event_ids"] = record["covered_event_ids"] + ["evt_ack_a"]
    result = verify_coverage(_parsed(record), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False


def test_range_extended_after_the_timestamp_leaves_new_events_uncovered(bundle):
    """AC-07. Moving last_seq forward pulls in events the token never committed to."""
    events = _events()
    record = _record(events, 0, 4)
    record["last_seq"] = 6
    result = verify_coverage(_parsed(record), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False


def test_checkpoint_before_finalisation_does_not_authenticate(bundle, monkeypatch):
    events = _events()
    monkeypatch.setattr(
        anchor_coverage,
        "verify_timestamp",
        lambda *a, **k: _StubTimestamp(gen_time="2026-10-21T08:00:00+00:00"),
    )
    result = verify_coverage(_parsed(_record(events, 0, 4)), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False
    assert any("precedes" in error for error in result.errors)


def test_untrusted_token_does_not_authenticate(bundle, monkeypatch):
    events = _events()
    monkeypatch.setattr(
        anchor_coverage,
        "verify_timestamp",
        lambda *a, **k: _StubTimestamp(trust_verified=False),
    )
    result = verify_coverage(_parsed(_record(events, 0, 4)), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False
    assert any("trust path" in error for error in result.errors)


def test_coverage_for_another_case_is_refused(bundle):
    """CP-01 at bundle granularity: a valid anchor for case B is not case A's."""
    events = _events()
    record = _record(events, 0, 4, case_id="case_2")
    result = verify_coverage(_parsed(record), events, bundle, manifest_case_id="case_1")
    assert result.authenticated is False
    assert any("case_2" in error for error in result.errors)


class _StubAppraisal:
    def __init__(self, satisfied: bool = True):
        self.satisfied = satisfied

    def summary(self) -> str:
        return "stub appraisal"


def test_action_covered_by_anchor_is_e4_and_appended_action_is_e3():
    """CP-07. The critical proof: coverage does not bleed forward."""
    events = _events()
    by_id = {event.event_id: event for event in events}
    coverage = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 0, 4)),
        authenticated=True,
        anchored_ids=frozenset(_record(events, 0, 4)["covered_event_ids"]),
    )
    pairs = {
        "evt_action_a": (by_id["evt_ack_a"], _StubAppraisal()),
        "evt_action_b": (by_id["evt_ack_b"], _StubAppraisal()),
    }
    actions = [by_id["evt_action_a"], by_id["evt_action_b"]]
    result = derive_action_grades(
        action_events=actions,
        action_corroboration=pairs,
        coverage_results=[coverage],
        integrity_grade=Grade.E2,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
    )
    assert result.action_grades == {"evt_action_a": Grade.E4, "evt_action_b": Grade.E3}
    # The summary is the weakest action, never the best one.
    assert result.evidence_grade == Grade.E3


def test_anchor_over_the_acknowledgement_alone_does_not_elevate():
    """CP-04. Coverage of the corroboration without its action is not E4."""
    events = _events()
    by_id = {event.event_id: event for event in events}
    partial = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 4, 4)),
        authenticated=True,
        anchored_ids=frozenset({"evt_ack_a"}),
    )
    pairs = {"evt_action_a": (by_id["evt_ack_a"], _StubAppraisal())}
    result = derive_action_grades(
        action_events=[by_id["evt_action_a"]],
        action_corroboration=pairs,
        coverage_results=[partial],
        integrity_grade=Grade.E2,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
    )
    assert result.action_grades["evt_action_a"] == Grade.E3


def test_second_anchor_promotes_the_later_action():
    events = _events()
    by_id = {event.event_id: event for event in events}
    first = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 0, 4, checkpoint_id="chk_1")),
        authenticated=True,
        anchored_ids=frozenset(i for i in _record(events, 0, 4)["covered_event_ids"]),
    )
    second = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 0, 6, checkpoint_id="chk_2")),
        authenticated=True,
        anchored_ids=frozenset(i for i in _record(events, 0, 6)["covered_event_ids"]),
    )
    pairs = {
        "evt_action_a": (by_id["evt_ack_a"], _StubAppraisal()),
        "evt_action_b": (by_id["evt_ack_b"], _StubAppraisal()),
    }
    result = derive_action_grades(
        action_events=[by_id["evt_action_a"], by_id["evt_action_b"]],
        action_corroboration=pairs,
        coverage_results=[first, second],
        integrity_grade=Grade.E2,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
    )
    assert result.action_grades == {"evt_action_a": Grade.E4, "evt_action_b": Grade.E4}


def test_later_anchor_does_not_reach_back_unrelated_evidence():
    """AC-05. An anchor over B alone leaves A at its own evidence."""
    events = _events()
    by_id = {event.event_id: event for event in events}
    only_b = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 5, 6)),
        authenticated=True,
        anchored_ids=frozenset({"evt_action_b", "evt_ack_b"}),
    )
    pairs = {
        "evt_action_a": (by_id["evt_ack_a"], _StubAppraisal()),
        "evt_action_b": (by_id["evt_ack_b"], _StubAppraisal()),
    }
    result = derive_action_grades(
        action_events=[by_id["evt_action_a"], by_id["evt_action_b"]],
        action_corroboration=pairs,
        coverage_results=[only_b],
        integrity_grade=Grade.E2,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
    )
    assert result.action_grades == {"evt_action_a": Grade.E3, "evt_action_b": Grade.E4}


def test_subject_action_names_the_top_level_grade():
    events = _events()
    by_id = {event.event_id: event for event in events}
    coverage = anchor_coverage.CoverageResult(
        record=_parsed(_record(events, 0, 4)),
        authenticated=True,
        anchored_ids=frozenset(i for i in _record(events, 0, 4)["covered_event_ids"]),
    )
    pairs = {
        "evt_action_a": (by_id["evt_ack_a"], _StubAppraisal()),
        "evt_action_b": (by_id["evt_ack_b"], _StubAppraisal()),
    }
    result = derive_action_grades(
        action_events=[by_id["evt_action_a"], by_id["evt_action_b"]],
        action_corroboration=pairs,
        coverage_results=[coverage],
        integrity_grade=Grade.E2,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
        subject_action_id="evt_action_a",
    )
    assert result.evidence_grade == Grade.E4
    assert result.action_grades["evt_action_b"] == Grade.E3
