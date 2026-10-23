# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Evidence grade derivation.

WitnessOS assigns evidence grades E1 through E4 based on what the verifier
has established for itself:

E1 — Observed:     events were produced by a source outside the acting agent
E2 — Enforced:     the action could not have occurred without the authorising
                   step, and the record set is cryptographically intact
E3 — Corroborated: a party other than the deployment, whose identity the
                   operator established independently, acknowledged the action
                   and named its own record of it
E4 — Anchored:     E3 plus an RFC 3161 timestamp, a Merkle inclusion proof and
                   authenticated external anchoring of that evidence

E4 requires legitimate E3 evidence plus independently authenticated external
anchoring. Retention is a separate attribute: `worm_valid` and
`retention_verified` report persistence and custody status and may be required
by deployment or compliance policy, but they do not move the evidence grade.
E4 establishes authenticated anchoring of E3 evidence; it does not by itself
claim long-term retention.

E3 is never taken from an event type, a provider name, a custody label or a
bundled key. It is taken from `CorroborationResult.satisfied`, which the
verifier computes in `corroboration.py`. A producer-written assertion can
describe evidence and cannot raise its grade.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .case_chain import ChainResult
from .corroboration import CorroborationResult
from .ledger import LedgerResult
from .manifest import ManifestResult
from .timestamp import TimestampResult
from .worm import WormResult


class Grade:
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"


@dataclass
class GradeResult:
    grade: str
    display: str
    requirements_met: List[str]
    requirements_missing: List[str]

    @property
    def is_e4(self) -> bool:
        return self.grade == Grade.E4

    @property
    def is_minimum_e3(self) -> bool:
        return self.grade in (Grade.E3, Grade.E4)


def derive_grade(
    events_loaded: bool,
    chain_result: Optional[ChainResult],
    ledger_result: Optional[LedgerResult],
    manifest_result: Optional[ManifestResult],
    corroboration: Optional[CorroborationResult],
    timestamp_result: Optional[TimestampResult],
    worm_result: Optional[WormResult],
    alpha_mode: bool = False,
    event_signatures_valid: bool = False,
    batch_binding_valid: bool = False,
    merkle_proof_valid: bool = False,
    observation_external: bool = False,
    enforcement_observed: bool = False,
    anchor_precedes_batch: bool = False,
    require_retention: bool = False,
    require_observer_identity: bool = False,
    observer_identity: Optional[str] = None,
) -> GradeResult:
    """Derive the evidence grade from verification results.

    Grade progression is cumulative:
    E1: events were produced outside the acting agent
    E2: E1 + chain valid + ledger valid + signatures valid + batch binding
    E3: E2 + a satisfied CorroborationResult
    E4: E3 + timestamp valid + Merkle proof valid

    Retention is reported as an attribute, never as a rung.

    `corroboration` is the verifier's own appraisal. There is deliberately no
    boolean parameter here: a caller cannot assert corroboration, only pass the
    result of an appraisal, and a missing appraisal caps at E2.
    """
    met = []
    missing = []

    # E1
    if not events_loaded:
        missing.append("E1: Events loaded")
        return GradeResult(grade=Grade.E0, display="No evidence loaded",
                          requirements_met=met, requirements_missing=missing)
    if not observation_external:
        met.append("E0: Agent-declared events only")
        missing.append("E1: No event observed outside the acting agent")
        return GradeResult(grade=Grade.E0, display="E0 — Declared",
                          requirements_met=met, requirements_missing=missing)
    met.append("E1: Observed outside the acting agent")

    # E1 as an identity claim, not merely a shape. The operator's provisioned
    # observer keys are the trust decision; without one, the record still shows
    # an observation but nobody can say who made it, and a caller that requires
    # identity gets the floor rather than a plausible rung.
    if require_observer_identity and not observer_identity:
        missing.append(
            "E1: Observer identity not established (no provisioned observer key signed this record)"
        )
        return GradeResult(
            grade=Grade.E0,
            display="E0 — Declared (observer identity unestablished)",
            requirements_met=met,
            requirements_missing=missing,
        )
    if observer_identity:
        met.append(f"E1: Observer identity established ({observer_identity})")

    # E2
    e2_ok = True
    if chain_result and chain_result.valid:
        met.append("E2: Case hash chain valid")
    else:
        missing.append("E2: Case hash chain invalid")
        e2_ok = False

    if ledger_result and ledger_result.valid and ledger_result.sequence_monotonic:
        met.append("E2: Ledger sequence valid")
    else:
        missing.append("E2: Ledger sequence invalid")
        e2_ok = False

    if manifest_result and manifest_result.valid:
        met.append("E2: Manifest signature valid")
    else:
        missing.append("E2: Manifest signature not verified")
        e2_ok = False

    for ok, label in [(event_signatures_valid, "Event signatures valid"), (batch_binding_valid, "Events bound to signed batch")]:
        (met if ok else missing).append("E2: " + label)
        e2_ok = e2_ok and ok

    (met if enforcement_observed else missing).append(
        "E2: Policy enforcement at a boundary recorded"
        if enforcement_observed
        else "E2: No enforcement point recorded the action (integrity alone is not enforcement)"
    )
    e2_ok = e2_ok and enforcement_observed

    if not e2_ok:
        return GradeResult(grade=Grade.E1, display="E1 — Observed",
                          requirements_met=met, requirements_missing=missing)
    grade = Grade.E2

    # E3
    corroborated = bool(corroboration is not None and corroboration.satisfied)
    if corroborated and corroboration is not None:
        met.append(f"E3: {corroboration.summary()}")
        grade = Grade.E3
    else:
        detail = (
            corroboration.summary()
            if corroboration is not None
            else "no corroboration was appraised"
        )
        missing.append(f"E3: {detail}")

    # E4
    e4_ok = merkle_proof_valid
    (met if merkle_proof_valid else missing).append("E4: Merkle inclusion proof valid")

    # A timestamp proves when a commitment existed. It does not decide what that
    # commitment belongs to, and it cannot cover a batch that claims to have been
    # finalised after the token was minted. Anchor validity and semantic binding
    # are two facts and both are required before E4.
    if anchor_precedes_batch:
        missing.append(
            "E4: Batch claims finalisation after its own checkpoint (anchor cannot cover later evidence)"
        )
        e4_ok = False
    else:
        met.append("E4: Checkpoint postdates the batch it anchors")

    if timestamp_result and timestamp_result.valid and timestamp_result.imprint_matches and getattr(timestamp_result, "signature_verified", False) and getattr(timestamp_result, "trust_verified", False):
        met.append("E4: RFC 3161 timestamp valid")
    else:
        missing.append("E4: RFC 3161 timestamp invalid or missing")
        e4_ok = False

    # The WORM evidence copy must be intact. An authenticated retention receipt is
    # an ATTRIBUTE: it is recorded and reported, and demanded only when the
    # operator's policy sets require_retention (docs/CUSTODY.md 7). Retention never
    # moves the grade, because a snapshot still existing was never evidence that
    # the statement is more true.
    retention_verified = bool(getattr(worm_result, "retention_verified", False))
    if worm_result and worm_result.valid and (retention_verified or not require_retention):
        met.append("E4: WORM evidence copy valid")
        met.append(
            "E4 attribute: authenticated retention receipt"
            if retention_verified
            else "E4 attribute: no retention receipt (attribute, not a grade requirement)"
        )
    else:
        missing.append("Attribute: authenticated WORM retention not established")

    if e4_ok and corroborated:
        if alpha_mode:
            # Alpha mode: E4 evidence exists but grade is capped at E3.
            # The timestamp and WORM checks passed, but we do not assert E4
            # until the system reaches production readiness.
            met.append("Alpha: E4 evidence present (capped at E3)")
            return GradeResult(
                grade=Grade.E3,
                display="E3 — Corroborated (Alpha — E4 capped)",
                requirements_met=met,
                requirements_missing=missing,
            )
        return GradeResult(
            grade=Grade.E4,
            display="E4 — Anchored",
            requirements_met=met,
            requirements_missing=missing,
        )

    if grade == Grade.E3:
        return GradeResult(
            grade=Grade.E3,
            display="E3 — Corroborated",
            requirements_met=met,
            requirements_missing=missing,
        )

    return GradeResult(
        grade=Grade.E2,
        display="E2 — Internally validated",
        requirements_met=met,
        requirements_missing=missing,
    )

@dataclass
class ActionGradeResult:
    """Grades that belong to actions, not to whatever bundle happens to hold them.

    `evidence_grade` is deliberately conservative. It is the grade of the subject
    action when one is named, otherwise the weakest grade in the case, because an
    aggregate that reports the best action lets the worst one free-ride. The
    per-action map is the authoritative answer and every consumer should say which
    action a grade belongs to.
    """

    action_grades: Dict[str, str] = field(default_factory=dict)
    evidence_grade: str = Grade.E0
    subject_action_id: Optional[str] = None
    basis: Dict[str, str] = field(default_factory=dict)
    requirements_met: List[str] = field(default_factory=list)
    requirements_missing: List[str] = field(default_factory=list)

    def display(self) -> str:
        if not self.action_grades:
            return f"{self.evidence_grade} — no governed action in this evidence"
        parts = ", ".join(f"{action}={grade}" for action, grade in sorted(self.action_grades.items()))
        return f"{self.evidence_grade} — action-scoped ({parts})"


_RANK = {Grade.E0: 0, Grade.E1: 1, Grade.E2: 2, Grade.E3: 3, Grade.E4: 4}


def derive_action_grades(
    action_events: Sequence,
    action_corroboration: Dict[str, Tuple],
    coverage_results: Sequence,
    integrity_grade: str,
    chain_of,
    subject_action_id: Optional[str] = None,
) -> ActionGradeResult:
    """Grade each governed action from the evidence that actually supports it.

    `integrity_grade` is what the record earns before corroboration (E0-E2). An
    action cannot outrank the integrity of the record that carries it, and an
    action whose acknowledgement is not satisfied cannot borrow another action's
    corroboration. E4 additionally requires one authenticated coverage record
    whose covered set contains the whole qualifying chain for that action, which
    is why an anchor over the acknowledgement alone never elevates anything.
    """
    result = ActionGradeResult(subject_action_id=subject_action_id)
    if _RANK.get(integrity_grade, 0) < _RANK[Grade.E2]:
        for event in action_events:
            result.action_grades[event.event_id] = integrity_grade
            result.basis[event.event_id] = "record integrity does not reach E2"
        result.evidence_grade = integrity_grade
        result.requirements_missing.append("E2: record integrity")
        return result

    for event in action_events:
        pair = action_corroboration.get(event.event_id)
        if pair is None:
            result.action_grades[event.event_id] = Grade.E2
            result.basis[event.event_id] = "no acknowledgement names this action"
            result.requirements_missing.append(
                f"E3: {event.event_id} has no acknowledgement binding it"
            )
            continue
        ack_event, appraisal = pair
        if not appraisal.satisfied:
            result.action_grades[event.event_id] = Grade.E2
            result.basis[event.event_id] = f"acknowledgement not corroborating: {appraisal.summary()}"
            result.requirements_missing.append(
                f"E3: {event.event_id} acknowledgement not corroborating: {appraisal.summary()}"
            )
            continue
        required = chain_of(event, ack_event)
        covering = [
            coverage
            for coverage in coverage_results
            if coverage.authenticated and required.issubset(coverage.anchored_ids)
        ]
        if covering:
            covering.sort(key=lambda c: c.record.last_seq)
            result.action_grades[event.event_id] = Grade.E4
            result.basis[event.event_id] = (
                f"covered by {covering[0].record.checkpoint_id} "
                f"(seq {covering[0].record.first_seq}-{covering[0].record.last_seq})"
            )
            result.requirements_met.append(
                f"E4: {event.event_id} covered by {covering[0].record.checkpoint_id}"
            )
        else:
            result.action_grades[event.event_id] = Grade.E3
            result.basis[event.event_id] = (
                "corroborated; no authenticated checkpoint covers its qualifying chain"
            )
            result.requirements_met.append(f"E3: {event.event_id} corroborated")

    if subject_action_id and subject_action_id in result.action_grades:
        result.evidence_grade = result.action_grades[subject_action_id]
    elif result.action_grades:
        weakest = min(result.action_grades.values(), key=lambda grade: _RANK.get(grade, 0))
        result.evidence_grade = weakest
    else:
        result.evidence_grade = integrity_grade
    return result
