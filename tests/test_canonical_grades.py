"""The evidence ladder, derived from evidence rather than asserted.

These tests replace four pre-audit fixtures that asserted E3 and E4 on a chain
that could not support either: a request, a legacy provider confirmation and an
anchor, with no executed action and no attestation bound to a provider record.
Under the hardened model that shape is E2, and it is kept below as a negative
regression so the change stays visible.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from canonical_fixtures import LEGACY_CHAIN, bundle, demanding, legacy_bundle, policy
from witnessos_verifier.events import load_events
from witnessos_verifier.verifier import verify

TSA = "https://tsa.fixture.invalid/tsr"


def test_canonical_e2_is_a_governed_action_without_corroboration():
    result = verify(bundle("canonical-e2"), trust_policy=policy("canonical-e2"), tsa_url=TSA)
    assert result.evidence_grade == "E2", result.grade.display
    assert not result.corroboration.satisfied
    assert "no corroboration" in " ".join(result.grade.requirements_missing).lower()


def test_canonical_e3_is_corroboration_without_a_trusted_anchor():
    result = verify(bundle("canonical-e3"), trust_policy=policy("canonical-e3"), tsa_url=TSA)
    assert result.evidence_grade == "E3", result.grade.display

    # E3 because the corroboration held, and only because the anchor could not
    # authenticate: the fixture publishes no CA for this package.
    assert result.corroboration.satisfied
    assert result.corroboration.subject_binding_valid
    assert result.corroboration.replay_check_passed
    assert not result.timestamp_result.valid
    assert any("trusted roots" in error for error in result.timestamp_result.errors)


def test_canonical_e4_is_e3_plus_an_authenticated_anchor():
    result = verify(bundle("canonical-e4"), trust_policy=policy("canonical-e4"), tsa_url=TSA)
    assert result.evidence_grade == "E4", result.grade.display

    assert result.corroboration.satisfied
    assert result.timestamp_result.valid
    assert result.timestamp_result.signature_verified
    assert result.timestamp_result.trust_verified
    assert [coverage.authenticated for coverage in result.anchor_coverages] == [True]


def test_retention_is_an_attribute_not_a_rung():
    result = verify(bundle("canonical-e4"), trust_policy=demanding("canonical-e4"), tsa_url=TSA)

    # Custody was demanded and not established: that is an attribute finding. It
    # changes neither the grade nor the evidence requirements.
    assert result.evidence_grade == "E4", result.grade.display
    assert any("Authenticated retention missing" in error for error in result.errors)

    # Any retention line in the requirement list is an attribute statement, not a
    # rung: nothing phrased as a grade requirement may depend on custody.
    retention_lines = [r for r in result.grade.requirements_missing if "retention" in r.lower()]
    assert all(line.startswith("Attribute") for line in retention_lines), retention_lines


def test_legacy_provider_confirmed_chain_cannot_self_promote_to_e3_or_e4():
    """The bug class this audit closed, kept as a permanent regression.

    A request, a policy decision, a dispatch, a legacy provider confirmation and
    an anchor with no executed action and no attestation bound to a retained
    provider record is not corroboration. It must not reach E3 or E4 however
    confidently it is labelled.
    """
    legacy = legacy_bundle()
    types = tuple(event.event_type for event in load_events(legacy))
    for expected in LEGACY_CHAIN:
        assert expected in types, f"the legacy fixture no longer models {expected}"
    assert "action.executed" not in types
    assert "provider.attestation" not in types

    result = verify(legacy)
    assert result.evidence_grade in ("E0", "E1", "E2"), result.grade.display
    assert not result.corroboration.satisfied
    assert "E4" not in result.grade.requirements_met


def test_an_awarded_grade_never_contradicts_its_own_requirements():
    """A verdict may not deny the rung it just awarded.

    The case-level appraisal always runs without corroboration, because the
    per-action appraisal is where corroboration is judged. Its missing list
    therefore says "no corroboration was appraised" even on a record whose action
    reached E3 or E4 from a satisfied appraisal. Carried into the verdict, that
    line contradicts the grade beside it: v1.1.0 published E4 with eleven
    requirements met and an E3 requirement reported missing.
    """
    for name, expected in (("canonical-e3", "E3"), ("canonical-e4", "E4")):
        result = verify(bundle(name), trust_policy=policy(name), tsa_url=TSA)
        assert result.evidence_grade == expected, (name, result.grade.display)
        assert result.corroboration.satisfied, name
        missing = " ".join(result.grade.requirements_missing).lower()
        assert "no corroboration was appraised" not in missing, (
            name, result.grade.requirements_missing)


def test_an_e2_verdict_still_names_the_missing_corroboration():
    """The fix must not silence the line where it is the whole point.

    A record with no satisfied corroboration is E2, and the verdict has to say
    that no corroboration was appraised rather than leaving the reader to infer
    it from a quiet requirements list.
    """
    result = verify(bundle("canonical-e2"), trust_policy=policy("canonical-e2"), tsa_url=TSA)
    assert result.evidence_grade == "E2", result.grade.display
    assert not result.corroboration.satisfied
    assert "no corroboration was appraised" in " ".join(
        result.grade.requirements_missing).lower()
