# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""End-to-end verification of the shipped demo bundle.

The demo bundle carries a `provider_confirmed` event signed by the same key as
every other event, and it publishes that key inside its own keys.json. Under the
corrected model that is not corroboration, so the bundle grades E2 and not E3,
and the E3 requirement is reported as missing rather than met. That downgrade is
deliberate: the earlier E3 depended on trusting the producer's own assertion.
"""
from pathlib import Path


class TestE2EVerification:
    def test_fixture_reports_unverified_anchor(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert not result.valid
        assert any("TSA signature" in e for e in result.errors)
        assert result.grade.grade == "E2"
        assert not result.timestamp_result.valid
        assert not result.worm_result.retention_verified

    def test_fixture_acknowledgement_is_not_corroboration(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert result.corroboration.present
        assert not result.corroboration.satisfied
        assert any("Corroboration not established" in w for w in result.warnings)

    def test_all_requirements_in_result(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        required = [
            "E1: Observed outside the acting agent",
            "E2: Case hash chain valid",
            "E2: Ledger sequence valid",
            "E2: Manifest signature valid",
            "E2: Event signatures valid",
            "E2: Events bound to signed batch",
            "E2: Policy enforcement at a boundary recorded",
        ]
        for req in required:
            assert req in result.grade.requirements_met, \
                f"Missing requirement: {req} (met: {result.grade.requirements_met})"

    def test_external_requirements_explicitly_missing(self, bundle_path):
        from witnessos_verifier.verifier import verify

        # Under the default policy the external requirements the verifier cannot
        # itself satisfy are named explicitly. Retention is no longer one of them:
        # it is an attribute (CUSTODY.md 7) and is reported separately, so a
        # missing receipt no longer appears as a missing requirement.
        result = verify(bundle_path)
        missing = result.grade.requirements_missing
        assert "E4: RFC 3161 timestamp invalid or missing" in missing, missing
        # The hardened model also names corroboration, which this package cannot
        # establish: it carries no attestation bound to a retained provider record.
        assert any("corroboration" in requirement.lower() for requirement in missing), missing


class TestCLIVerify:
    def test_cli_verify_output(self, bundle_path):
        import subprocess

        exe = Path(__file__).parent.parent / ".venv" / "bin" / "witnessos-verifier"
        result = subprocess.run(
            [str(exe), "verify", str(bundle_path)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, f"CLI failed: {result.stderr}"
        assert "Grade:  E2" in result.stdout
        assert "TSA:     FAIL" in result.stdout


class TestEmptyBundle:
    def test_empty_bundle_graceful(self, tmp_path):
        from witnessos_verifier.verifier import verify

        (tmp_path / "empty").mkdir()
        result = verify(tmp_path / "empty")
        assert result.grade is None, f"Expected grade=None, got {result.grade}"
        assert "Events directory not found" in str(result.errors)
