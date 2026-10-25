# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0

"""Foundation profile: what the verifier refuses to award, and why it says so.

The profile is a normative gate, not a label. A record whose authorship is not
established cannot reach E2 no matter how tidy its hash chain is, and an anchor
lifts nothing until the operator's trust policy authenticates it.
"""
from __future__ import annotations

from witnessos_verifier.case_chain import ChainResult
from witnessos_verifier.grades import (
    Grade,
    derive_action_grades,
    derive_grade,
)
from witnessos_verifier.ledger import LedgerResult
from witnessos_verifier.manifest import ManifestResult


def _valid_chain() -> ChainResult:
    return ChainResult(valid=True, total_events=3, verified_links=2, errors=[])


def _valid_ledger() -> LedgerResult:
    return LedgerResult(valid=True, sequence_monotonic=True, head_consistent=True, errors=[])


def _valid_manifest() -> ManifestResult:
    return ManifestResult(
        valid=True,
        manifest=None,
        key_found=True,
        key_valid=True,
        signature_valid=True,
        errors=[],
    )


def _grade(**overrides):
    kwargs = dict(
        events_loaded=True,
        chain_result=_valid_chain(),
        ledger_result=_valid_ledger(),
        manifest_result=_valid_manifest(),
        corroboration=None,
        timestamp_result=None,
        worm_result=None,
        event_signatures_valid=True,
        batch_binding_valid=True,
        merkle_proof_valid=True,
        observation_external=True,
        enforcement_observed=True,
    )
    kwargs.update(overrides)
    return derive_grade(**kwargs)


class TestFoundationGates:
    def test_authenticated_bound_record_reaches_e2(self):
        result = _grade()
        assert result.grade == Grade.E2
        assert "corroboration" in result.cap_reason

    def test_missing_signature_cannot_reach_e2(self):
        result = _grade(event_signatures_valid=False)
        assert result.grade == Grade.E1
        assert "signatures are missing or invalid" in result.cap_reason
        assert any("Foundation" in item for item in result.requirements_missing)

    def test_invalid_signature_cannot_reach_e2(self):
        result = _grade(event_signatures_valid=False, chain_result=_valid_chain())
        assert result.grade == Grade.E1
        assert result.cap_reason.startswith("Foundation profile")

    def test_wrong_signing_identity_cannot_reach_e2(self):
        """A signature by a key the registry does not hold is not a signature."""
        result = _grade(event_signatures_valid=False, observer_identity=None)
        assert result.grade == Grade.E1

    def test_missing_batch_binding_cannot_reach_e2(self):
        result = _grade(batch_binding_valid=False)
        assert result.grade == Grade.E1
        assert "not bound to a signed batch" in result.cap_reason

    def test_e3_requires_valid_e2(self):
        class _Appraisal:
            satisfied = True

            def summary(self) -> str:
                return "provider record verified"

        class _Action:
            event_id = "act-1"

        result = derive_action_grades(
            action_events=[_Action()],
            action_corroboration={"act-1": (object(), _Appraisal())},
            coverage_results=[],
            integrity_grade=Grade.E1,
            chain_of=lambda action, ack: set(),
        )
        # A satisfied corroboration cannot lift a record whose integrity is E1.
        assert result.evidence_grade == Grade.E1
        assert result.basis["act-1"] == "record integrity does not reach E2" 

    def test_e4_requires_an_authenticated_anchor(self):
        class _Action:
            event_id = "act-1"

        class _Coverage:
            authenticated = False
            record = type(
                "Record",
                (),
                {
                    "checkpoint_id": "cp-1",
                    "first_seq": 1,
                    "last_seq": 3,
                },
            )()
            anchored_ids = {"act-1"}
            errors = ["TSA certificate is not under a trusted root"]

        class _Appraisal:
            satisfied = True

            def summary(self) -> str:
                return "provider record verified"

        result = derive_action_grades(
            action_events=[_Action()],
            action_corroboration={"act-1": (object(), _Appraisal())},
            coverage_results=[_Coverage()],
            integrity_grade=Grade.E2,
            chain_of=lambda action, ack: {"act-1"},
        )
        assert result.evidence_grade == Grade.E3
        assert "authenticated checkpoint" in result.basis["act-1"]

    def test_authenticated_anchor_reaches_e4(self):
        class _Action:
            event_id = "act-1"

        class _Coverage:
            authenticated = True
            record = type(
                "Record",
                (),
                {"checkpoint_id": "cp-1", "first_seq": 1, "last_seq": 3},
            )()
            anchored_ids = {"act-1"}
            errors = []

        class _Appraisal:
            satisfied = True

            def summary(self) -> str:
                return "provider record verified"

        result = derive_action_grades(
            action_events=[_Action()],
            action_corroboration={"act-1": (object(), _Appraisal())},
            coverage_results=[_Coverage()],
            integrity_grade=Grade.E2,
            chain_of=lambda action, ack: {"act-1"},
        )
        assert result.evidence_grade == Grade.E4


class TestLegacyCompatibility:
    def test_legacy_profile_keeps_the_historical_ordering(self):
        result = _grade(profile="legacy", batch_binding_valid=False)
        assert result.grade == Grade.E1
        assert result.cap_reason == ""

    def test_foundation_profile_names_the_cap(self):
        result = _grade(profile="foundation", batch_binding_valid=False)
        assert result.cap_reason.startswith("Foundation profile")
