# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Test end-to-end verification of E4 fixture."""
from pathlib import Path


class TestE2EVerification:
    def test_fixture_reports_unverified_anchor(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert not result.valid
        assert any("TSA signature" in e for e in result.errors)
        assert result.grade.grade == "E3"
        assert not result.timestamp_result.valid
        assert not result.worm_result.retention_verified

    def test_all_requirements_in_result(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        required = [
            "E1: Events loaded",
            "E2: Case hash chain valid",
            "E2: Ledger sequence valid",
            "E2: Manifest signature valid",
            "E3: Provider acknowledged",
            "E2: Event signatures valid",
            "E2: Events bound to signed batch",
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
        assert result.grade.requirements_missing == ["E4: RFC 3161 timestamp invalid or missing"], \
            f"Missing requirements: {result.grade.requirements_missing}"


class TestCLIVerify:
    def test_cli_verify_output(self, bundle_path):
        import subprocess

        exe = Path(__file__).parent.parent / ".venv" / "bin" / "witnessos-verifier"
        result = subprocess.run(
            [str(exe), "verify", str(bundle_path)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, f"CLI failed: {result.stderr}"
        assert "Grade:  E3" in result.stdout
        assert "TSA:     FAIL" in result.stdout


class TestEmptyBundle:
    def test_empty_bundle_graceful(self, tmp_path):
        from witnessos_verifier.verifier import verify

        (tmp_path / "empty").mkdir()
        result = verify(tmp_path / "empty")
        assert result.grade is None, f"Expected grade=None, got {result.grade}"
        assert "Events directory not found" in str(result.errors)
