# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Evidence-grade audit (MOP-WITNESSOS-EVIDENCE-GRADE-AUDIT-001).

Every case here is a permanent regression fixture. Before this suite existed, a
bundle written end to end by one party, with that party's own key in its own
keys.json and an acknowledgement it wrote and signed itself, verified as E3 and,
with any real RFC 3161 anchor, as E4. The cases below hold that closed.

Naming follows the audit matrix: EG-nn.
"""
from __future__ import annotations

import json

import pytest

from tests.hostile import factory
from witnessos_verifier.corroboration import CorroborationResult
from witnessos_verifier.grades import derive_grade
from witnessos_verifier.verifier import verify


def grade_of(path, policy=None):
    return verify(path, trust_policy=policy)


class _R:
    """Stand-in for a result object with .valid (+ optional fields)."""

    def __init__(self, valid=True, **kw):
        self.valid = valid
        for k, v in kw.items():
            setattr(self, k, v)


def _anchor_results():
    return dict(
        chain_result=_R(True),
        ledger_result=_R(True, sequence_monotonic=True),
        manifest_result=_R(True),
        timestamp_result=_R(True, imprint_matches=True, signature_verified=True, trust_verified=True),
        worm_result=_R(True, retention_verified=True),
        event_signatures_valid=True,
        batch_binding_valid=True,
        merkle_proof_valid=True,
        observation_external=True,
        enforcement_observed=True,
    )


def _satisfied():
    return CorroborationResult(
        present=True,
        source_party="Stripe",
        source_type="provider_acknowledgement",
        source_record_id="ch_test_record_1",
        source_record_digest="a" * 64,
        signer_identity="Stripe",
        signer_identity_verified=True,
        independent_of_deployment=True,
        subject_binding_valid=True,
        provenance_verified=True,
        replay_check_passed=True,
        cryptographic_integrity_valid=True,
    )


# ---------------------------------------------------------------- positive control

def test_honest_bundle_with_provisioned_provider_reaches_e3(tmp_path):
    """The ladder still reaches E3 when corroboration is genuine."""
    built = factory.build(tmp_path / "honest")
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E3", result.grade.requirements_missing
    assert result.corroboration.satisfied
    assert result.corroboration.source_party == "Stripe-test"


def test_satisfied_corroboration_with_full_anchor_reaches_e4():
    """E4 is E3 custody plus an anchor, and still reachable."""
    result = derive_grade(
        events_loaded=True, corroboration=_satisfied(), **_anchor_results()
    )
    assert result.grade == "E4"


# ---------------------------------------------------------------- EG-01 .. EG-15

def test_eg01_producer_declared_grade_is_ignored(tmp_path):
    built = factory.build(tmp_path / "eg01", ack="absent", declared_grade="E4")
    manifest = json.loads((built["path"] / "batch_manifest.json").read_text())
    assert manifest["grade"] == "E4"  # the claim is really in the record
    result = grade_of(built["path"])
    assert result.evidence_grade == "E2"


def test_eg02_self_signed_provider_confirmation_caps_at_e2(tmp_path):
    built = factory.build(tmp_path / "eg02", ack="self")
    # Even when the operator is tricked into provisioning the deployment's own
    # key as if it belonged to a provider, the key signed the rest of the
    # evidence, so it is the deployment agreeing with itself.
    policy = factory.policy(built["deployment_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert result.corroboration.present
    assert not result.corroboration.independent_of_deployment


def test_eg03_anchor_cannot_repair_missing_corroboration():
    """A real anchor over uncorroborated bytes stays at E2."""
    result = derive_grade(
        events_loaded=True,
        corroboration=CorroborationResult(present=True, reasons=("signed by the deployment",)),
        **_anchor_results(),
    )
    assert result.grade == "E2"


def test_eg04_provider_name_only_caps_at_e2(tmp_path):
    built = factory.build(tmp_path / "eg04", provider_ref=False)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.provenance_verified


def test_eg05_bundled_provider_key_is_not_identity(tmp_path):
    built = factory.build(tmp_path / "eg05", ack="unprovisioned")
    keys = json.loads((built["path"] / "keys.json").read_text())
    assert any(k["public_key_hex"] == built["unprovisioned_public_hex"] for k in keys)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.signer_identity_verified


def test_eg06_self_referential_provenance_gains_nothing(tmp_path):
    built = factory.build(tmp_path / "eg06", self_digest=True)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.provenance_verified


def test_eg07_unknown_custody_labels_do_not_establish_independence(tmp_path):
    built = factory.build(tmp_path / "eg07", ack="unprovisioned", custody_label="EXTERNAL")
    ack_files = [p for p in sorted((built["path"] / "events").glob("*.json")) if "provider_" in p.read_text()]
    payload = json.loads(ack_files[-1].read_text())["payload"]
    assert payload["custody"] == "EXTERNAL" and payload["basis_engine"] == "external_authority"
    result = grade_of(built["path"], factory.policy(built["provider_public_hex"]))
    assert result.evidence_grade == "E2"


def test_eg08_second_component_of_the_same_deployment_is_not_corroboration(tmp_path):
    built = factory.build(tmp_path / "eg08", ack="same_deployment")
    policy = factory.policy(built["same_deployment_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.independent_of_deployment


def test_eg09_replayed_acknowledgement_fails(tmp_path):
    built = factory.build(tmp_path / "eg09", replay_binding=False)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.replay_check_passed


def test_eg10_acknowledgement_for_another_subject_fails(tmp_path):
    built = factory.build(tmp_path / "eg10", subject_binding=False)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.subject_binding_valid


def test_eg11_tampered_acknowledgement_is_refused(tmp_path):
    built = factory.build(tmp_path / "eg11", tamper_ack_after_sign=True)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert not result.valid
    assert result.evidence_grade in ("E0", "E1")
    assert not (result.corroboration and result.corroboration.satisfied)


def test_eg12_full_anchor_without_corroboration_caps_at_e2():
    result = derive_grade(events_loaded=True, corroboration=None, **_anchor_results())
    assert result.grade == "E2"


def test_eg13_corroboration_without_enforcement_cannot_skip_e2(tmp_path):
    built = factory.build(tmp_path / "eg13", enforcement=False)
    policy = factory.policy(built["provider_public_hex"])
    result = grade_of(built["path"], policy)
    assert result.corroboration.satisfied  # the corroboration is genuine
    assert result.evidence_grade == "E1"  # but E2 was never established
    assert any("No enforcement point" in m for m in result.grade.requirements_missing)


def test_eg14_agent_declaration_only_is_e0(tmp_path):
    built = factory.build(tmp_path / "eg14", ack="absent", observation=False)
    result = grade_of(built["path"])
    assert result.evidence_grade == "E0"


def test_eg15_integrity_without_enforcement_is_not_e2(tmp_path):
    """A valid hash chain, ledger and manifest are record integrity, not policy."""
    built = factory.build(tmp_path / "eg15", ack="absent", enforcement=False)
    result = grade_of(built["path"])
    assert result.manifest_result.valid and result.ledger_result.valid
    assert result.evidence_grade == "E1"


# ---------------------------------------------------------------- properties

def test_property_producer_assertions_never_raise_the_grade(tmp_path):
    """Adding only producer-controlled assertions cannot change the grade."""
    base = factory.build(tmp_path / "prop-base", ack="self")
    plain = grade_of(base["path"], factory.policy(base["deployment_public_hex"])).evidence_grade

    dressed = factory.build(
        tmp_path / "prop-dressed",
        ack="self",
        declared_grade="E4",
        custody_label="EXTERNAL",
    )
    dressed_grade = grade_of(
        dressed["path"], factory.policy(dressed["deployment_public_hex"])
    ).evidence_grade
    assert dressed_grade == plain == "E2"


def test_property_removing_independent_evidence_only_lowers(tmp_path):
    built = factory.build(tmp_path / "prop-remove")
    with_policy = grade_of(built["path"], factory.policy(built["provider_public_hex"]))
    without_policy = grade_of(built["path"], factory.policy(None))
    assert with_policy.evidence_grade == "E3"
    assert without_policy.evidence_grade == "E2"


@pytest.mark.parametrize("observation,enforcement", [(False, True), (True, False), (False, False)])
def test_property_anchor_cannot_lift_uncorroborated_evidence_to_e4(observation, enforcement):
    results = _anchor_results()
    results["observation_external"] = observation
    results["enforcement_observed"] = enforcement
    result = derive_grade(
        events_loaded=True,
        corroboration=CorroborationResult(present=True, reasons=("not established",)),
        **results,
    )
    assert result.grade in ("E0", "E1", "E2")


def test_no_trust_policy_means_no_e3(tmp_path):
    """Fail closed: without operator trust input nothing can be attributed."""
    built = factory.build(tmp_path / "no-policy")
    result = grade_of(built["path"], None)
    assert result.evidence_grade == "E2"
    assert not result.corroboration.satisfied
