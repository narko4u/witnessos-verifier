"""F4: a substantive failure must never leave a corroboration looking satisfied.

An altered provider record is the negative F4 names explicitly. The verifier used
to report the digest mismatch in its reasons while still calling the corroboration
satisfied, because the verdict type had no field for the substantive check. These
tests keep that field load-bearing.
"""

from __future__ import annotations

from witnessos_verifier.corroboration_types import CorroborationResult
from witnessos_verifier.verifier import _rung_of


def _satisfied(**overrides) -> CorroborationResult:
    base = dict(
        present=True,
        signer_identity="Foundation Provider (independent)",
        signer_identity_verified=True,
        independent_of_deployment=True,
        subject_binding_valid=True,
        provenance_verified=True,
        replay_check_passed=True,
        cryptographic_integrity_valid=True,
        substantive_valid=True,
    )
    base.update(overrides)
    return CorroborationResult(**base)


def test_substantive_failure_blocks_satisfied():
    assert _satisfied().satisfied is True
    assert _satisfied(substantive_valid=False).satisfied is False


def test_substantive_default_is_not_permissive():
    assert CorroborationResult(present=True).satisfied is False


def test_rung_of_reads_rungs_and_ignores_attributes():
    assert _rung_of("E3: no corroboration was appraised") == 3
    assert _rung_of("E4: RFC 3161 timestamp invalid or missing") == 4
    assert _rung_of("E4 attribute: retention custody") is None
    assert _rung_of("Attribute: authenticated WORM retention not established") is None
    assert _rung_of("not a rung at all") is None
