# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Evidence grade derivation.

WitnessOS assigns evidence grades E1 through E4 based on what
has been cryptographically verified:

E1 — Observed: Events exist, loaded successfully
E2 — Internally validated: Case hash chain intact, ledger monotonic,
     event hashes verified, signatures valid
E3 — Destination acknowledged: Provider (Gmail, Stripe) confirmed the
     action via a provider_acknowledged or provider_confirmed event
E4 — Externally anchored: RFC 3161 timestamp + Merkle inclusion proof
     + WORM evidence copy — independently verifiable by anyone
"""

from dataclasses import dataclass
from typing import List, Optional

from .case_chain import ChainResult
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
    has_provider_ack: bool,
    timestamp_result: Optional[TimestampResult],
    worm_result: Optional[WormResult],
    alpha_mode: bool = False,
    event_signatures_valid: bool = False,
    batch_binding_valid: bool = False,
    merkle_proof_valid: bool = False,
    require_retention: bool = False,
) -> GradeResult:
    """Derive the evidence grade from verification results.

    Grade progression is cumulative:
    E1: Events loaded successfully
    E2: E1 + chain valid + ledger valid + signatures valid
    E3: E2 + provider acknowledged the action
    E4: E3 + timestamp valid + Merkle proof valid + WORM copy valid
    """
    met = []
    missing = []

    # E1
    if events_loaded:
        met.append("E1: Events loaded")
    else:
        missing.append("E1: Events loaded")
        return GradeResult(grade=Grade.E0, display="No evidence loaded",
                          requirements_met=met, requirements_missing=missing)

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

    if not e2_ok:
        return GradeResult(grade=Grade.E1, display="E1 — Observed",
                          requirements_met=met, requirements_missing=missing)
    grade = Grade.E2

    # E3
    if has_provider_ack:
        met.append("E3: Provider acknowledged")
        grade = Grade.E3
    else:
        missing.append("E3: No provider acknowledgement found")

    # E4
    e4_ok = merkle_proof_valid
    (met if merkle_proof_valid else missing).append("E4: Merkle inclusion proof valid")

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
        missing.append("E4: Authenticated WORM retention evidence invalid or missing")
        e4_ok = False

    if e4_ok and has_provider_ack:
        if alpha_mode:
            # Alpha mode: E4 evidence exists but grade is capped at E3.
            # The timestamp and WORM checks passed, but we do not assert E4
            # until the system reaches production readiness.
            met.append("Alpha: E4 evidence present (capped at E3)")
            return GradeResult(
                grade=Grade.E3,
                display="E3 — Destination acknowledged (Alpha — E4 capped)",
                requirements_met=met,
                requirements_missing=missing,
            )
        return GradeResult(
            grade=Grade.E4,
            display="E4 — Externally anchored",
            requirements_met=met,
            requirements_missing=missing,
        )

    if grade == Grade.E3:
        return GradeResult(
            grade=Grade.E3,
            display="E3 — Destination acknowledged",
            requirements_met=met,
            requirements_missing=missing,
        )

    return GradeResult(
        grade=Grade.E2,
        display="E2 — Internally validated",
        requirements_met=met,
        requirements_missing=missing,
    )
