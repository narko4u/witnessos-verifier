# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Regression tests for E3/E4 grade integrity.

History: the 2026-09-08 fixes taught the verifier to recognise both
acknowledgement vocabularies and made E4 require E3. The 2026-10-21 audit
(MOP-WITNESSOS-EVIDENCE-GRADE-AUDIT-001) found that both fixes still rested on a
naked boolean: any bundle could carry a `provider.confirmed` event it signed
itself and reach E3, then E4 with an anchor. E3 is now taken from a verifier
appraisal (`CorroborationResult`) rather than from the presence of an event type,
so the tests below construct the appraisal explicitly.
"""


class _R:
    """Minimal stand-in for a result object with .valid (+ optional fields)."""
    def __init__(self, valid=True, **kw):
        self.valid = valid
        for k, v in kw.items():
            setattr(self, k, v)


def _corroborated():
    from witnessos_verifier.corroboration import CorroborationResult
    return CorroborationResult(
        present=True,
        source_party="Stripe",
        source_type="provider_acknowledgement",
        source_record_id="ch_test_record_1",
        source_record_digest="b" * 64,
        signer_identity="Stripe",
        signer_identity_verified=True,
        independent_of_deployment=True,
        subject_binding_valid=True,
        provenance_verified=True,
        replay_check_passed=True,
        cryptographic_integrity_valid=True,
    )


def _uncorroborated():
    from witnessos_verifier.corroboration import CorroborationResult
    return CorroborationResult(present=True, reasons=("signed by the deployment itself",))


class TestE3VocabularyBothForms:
    """The vocabulary is still recognised; recognising it no longer awards E3."""

    def test_dot_vocabulary_acknowledged(self, bundle_path):
        from witnessos_verifier.verifier import verify
        stripe = bundle_path.parent / "e4-stripe-refund"
        from witnessos_verifier.events import load_events
        from witnessos_verifier.verifier import PROVIDER_ACK_TYPES
        assert any(e.event_type in PROVIDER_ACK_TYPES for e in load_events(stripe))
        result = verify(stripe)
        assert not result.valid  # the default policy cannot verify the external TSA
        # Retention is an attribute: an absent receipt is reported, never failed.
        assert "Authenticated retention missing" in " ".join(result.warnings)
        assert not any("Authenticated retention missing" in e for e in result.errors)
        # Recognising the vocabulary is not corroboration. This legacy package has
        # a provider confirmation but no executed action and no attestation bound
        # to a retained provider record, so it stays where the facts put it.
        assert result.evidence_grade == "E2"
        assert not result.corroboration.satisfied

    def test_dot_vocabulary_confirmed(self):
        from witnessos_verifier.grades import derive_grade
        gr = derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            observation_external=True,
            enforcement_observed=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            corroboration=_corroborated(),
            timestamp_result=_R(True, imprint_matches=True, signature_verified=True, trust_verified=True),
            worm_result=_R(True, retention_verified=True),
        )
        assert gr.grade == "E4"


class TestE4RequiresE3:
    """E4 must never be awarded without established corroboration."""

    def _grade_with(self, corroboration, tsa_ok=True, worm_ok=True, alpha=False):
        from witnessos_verifier.grades import derive_grade
        return derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            observation_external=True,
            enforcement_observed=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            corroboration=corroboration,
            timestamp_result=_R(tsa_ok, imprint_matches=tsa_ok, signature_verified=tsa_ok, trust_verified=tsa_ok),
            worm_result=_R(worm_ok, retention_verified=worm_ok),
            alpha_mode=alpha,
        )

    def test_no_corroboration_tsa_present_caps_below_e4(self):
        gr = self._grade_with(_uncorroborated())
        assert gr.grade == "E2", f"Expected cap at E2, got {gr.grade}"
        assert any(m.startswith("E3:") for m in gr.requirements_missing)

    def test_missing_appraisal_caps_below_e4(self):
        gr = self._grade_with(None)
        assert gr.grade == "E2"

    def test_full_e4_requires_corroboration(self):
        gr = self._grade_with(_corroborated())
        assert gr.grade == "E4"

    def test_alpha_caps_e4_to_e3_only_with_corroboration(self):
        assert self._grade_with(_corroborated(), alpha=True).grade == "E3"
        assert self._grade_with(_uncorroborated(), alpha=True).grade == "E2"
