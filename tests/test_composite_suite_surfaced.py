"""A passing verdict on a hybrid record has to say that it is one.

The composite path was verified and never reported. A counterparty running the
standard verify against a post-quantum hybrid record saw `Manifest: PASS` and no
mention of ML-DSA-65 anywhere in the output, so the one property that makes the
record post-quantum was checked and invisible at the same time. For a reader the
two are indistinguishable: an unstated property is an absent one.

These tests pin the surfacing, both in the printed summary and in the JSON a
counterparty scripts against.
"""

import base64
import json
from pathlib import Path

from click.testing import CliRunner

from tests.test_composite_manifest import _base, _composite, _mk, _registry
from witnessos_verifier.cli import main
from witnessos_verifier.manifest import BatchManifest, verify_manifest
from witnessos_verifier.verifier import VerifyResult

SHIPPED_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "e4-stripe-refund"


def _v1(tmp_path):
    """A valid version 1 manifest, for the control case."""
    p_sk, p_pub = _mk("Ed25519")
    _c_sk, c_pub = _mk("ML-DSA-65")
    d = _base(signature="AA==")
    p = tmp_path / "v1.json"
    p.write_text(json.dumps(d))
    manifest = BatchManifest.from_file(p)
    d["signature"] = base64.b64encode(p_sk.sign(manifest.signed_data)).decode()
    p.write_text(json.dumps(d))
    return p, _registry(p_pub, c_pub)


def test_the_summary_names_the_suite_on_a_composite_record(tmp_path):
    path, registry = _composite(tmp_path)
    verdict = verify_manifest(BatchManifest.from_file(path), registry)
    assert verdict.valid, verdict.errors
    result = VerifyResult(bundle_path=Path("/nonexistent/bundle"), valid=True,
                          manifest_result=verdict)
    assert result.manifest_suite == "ed25519+ml-dsa-65"
    assert result.composite is True
    assert "ed25519+ml-dsa-65" in result.summary()


def test_the_suite_is_absent_from_the_summary_on_a_classical_record(tmp_path):
    """No suite line where there is no suite. The control for the test above."""
    path, registry = _v1(tmp_path)
    verdict = verify_manifest(BatchManifest.from_file(path), registry)
    assert verdict.valid, verdict.errors
    result = VerifyResult(bundle_path=Path("/nonexistent/bundle"), valid=True,
                          manifest_result=verdict)
    assert result.manifest_suite == ""
    assert result.composite is False
    assert "Suite:" not in result.summary()


def test_the_suite_is_reported_even_when_the_record_fails(tmp_path):
    """A failing hybrid record must still name its suite, or the reader cannot see why."""
    path, registry = _composite(tmp_path)
    data = json.loads(path.read_text())
    data["countersignature"] = base64.b64encode(b"\x00" * 64).decode()
    path.write_text(json.dumps(data))
    verdict = verify_manifest(BatchManifest.from_file(path), registry)
    assert verdict.valid is False
    result = VerifyResult(bundle_path=Path("/nonexistent/bundle"), valid=False,
                          manifest_result=verdict)
    assert result.manifest_suite == "ed25519+ml-dsa-65"
    assert "Suite:" in result.summary()


def test_the_json_verdict_carries_the_suite_keys():
    """The machine-readable verdict is what a counterparty scripts against."""
    result = CliRunner().invoke(main, ["verify", str(SHIPPED_FIXTURE), "--json"])
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.output)
    assert "manifest_suite" in payload, "the JSON verdict does not report the suite"
    assert "composite" in payload, "the JSON verdict does not report whether the record is composite"
    assert payload["composite"] is False, "a classical fixture was reported as composite"


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-v"]))
