"""The shipped hybrid example must still verify with the shipped code.

`examples/engine-record/` is the record a counterparty is pointed at, and its
`RECEIPT.txt` is the printed evidence that a post-quantum hybrid signature, an
offline Merkle anchor and a real external timestamp can all be checked with no
Empire Labs party in the loop. That is a market claim resting on a directory of
static files.

Nothing verified it. The suite exercised `engine_native` against manifests built
in `tmp_path`, so the module was covered while the artefact it exists to produce
was not. A format change, a canonicaliser drift or a fixture edit would leave the
example and its receipt disagreeing with the code, and the suite would stay
green while the demonstrated claim became false.

These tests bind the artefact to the code. They are deliberately read-only
against the checked-in example: a repair must be a deliberate edit, not a
silent regeneration.
"""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from witnessos_verifier.cli import main
from witnessos_verifier.engine_native import verify_engine_anchor, verify_engine_manifest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "engine-record"


def _manifest() -> dict:
    return json.loads((EXAMPLE / "manifest.json").read_text(encoding="utf-8"))


def _keys() -> dict:
    return {k["key_id"]: k for k in json.loads((EXAMPLE / "keys.json").read_text(encoding="utf-8"))}


def _leaves() -> list:
    return [x["global_event_hash"]
            for x in json.loads((EXAMPLE / "leaves.json").read_text(encoding="utf-8"))["leaves"]]


def test_the_example_directory_is_whole():
    for name in ("manifest.json", "keys.json", "leaves.json", "timestamp.tsr", "RECEIPT.txt", "README.md"):
        assert (EXAMPLE / name).is_file(), f"the shipped example is missing {name}"


def test_the_shipped_example_is_hybrid():
    """Two schemes, two distinct keys. A single-scheme example would not carry the claim."""
    m = _manifest()
    suite = m.get("sig_algorithm", "")
    labels = [p.strip().lower() for p in suite.split("+") if p.strip()]
    assert len(labels) == 2, f"example declares suite {suite!r}, expected two schemes"
    assert m.get("signer_key_id") != m.get("countersigner_key_id"), "both halves use the same key"
    assert m.get("signature"), "example carries no primary signature"
    assert m.get("countersignature"), "example carries no countersignature"


def test_the_suite_matches_the_keys_the_record_ships():
    """The record must be self-describing: the declared suite equals what its own keys say."""
    m = _manifest()
    keys = _keys()
    declared = {str(keys[m["signer_key_id"]]["algorithm"]).strip().lower(),
                str(keys[m["countersigner_key_id"]]["algorithm"]).strip().lower()}
    labels = {p.strip().lower() for p in str(m["sig_algorithm"]).split("+") if p.strip()}
    assert declared == labels, f"suite {labels} does not match the shipped keys {declared}"


def test_the_shipped_signature_verifies_with_the_engine_absent():
    verdict = verify_engine_manifest(_manifest(), _keys())
    assert verdict["valid"] is True, verdict["errors"]
    assert verdict["composite"] is True
    assert verdict["halves"] == {"primary": True, "counter": True}


def test_the_shipped_anchor_reproduces_from_the_shipped_leaves():
    verdict = verify_engine_anchor(_manifest(), _leaves())
    assert verdict["valid"] is True, verdict["errors"]
    assert verdict["recomputed"] == verdict["declared"]


def _flip_a_hex_digit(value: str) -> str:
    """Change one bit of a hex value while keeping its `sha256:` prefix and length."""
    prefix, sep, body = value.partition(":")
    if not sep:
        prefix, body = "", value
    flipped = "0" if body[0] != "0" else "1"
    body = flipped + body[1:]
    return f"{prefix}:{body}" if sep else body


def test_a_tampered_leaf_breaks_the_shipped_anchor():
    """The anchor claim is only worth anything if it can fail."""
    m = _manifest()
    leaves = _leaves()
    leaves[0] = _flip_a_hex_digit(leaves[0])
    verdict = verify_engine_anchor(m, leaves)
    assert verdict["valid"] is False
    assert any("Merkle root mismatch" in e for e in verdict["errors"])


def test_a_malformed_leaf_is_refused_rather_than_raising():
    """An unverifiable record must come back as unverifiable, not as a stack trace."""
    m = _manifest()
    leaves = _leaves()
    leaves[0] = "not-hexadecimal"
    verdict = verify_engine_anchor(m, leaves)
    assert verdict["valid"] is False
    assert any("not hex" in e for e in verdict["errors"])


def test_the_cli_refuses_a_malformed_leaf_without_a_traceback(tmp_path):
    copy = tmp_path / "engine-record"
    shutil.copytree(EXAMPLE, copy)
    leaves = json.loads((copy / "leaves.json").read_text(encoding="utf-8"))
    leaves["leaves"][0]["global_event_hash"] = "not-hexadecimal"
    (copy / "leaves.json").write_text(json.dumps(leaves), encoding="utf-8")
    result = CliRunner().invoke(main, ["verify-engine", str(copy)])
    assert result.exit_code == 1, result.output
    assert "Traceback" not in result.output, result.output


def test_a_stripped_counter_half_breaks_the_primary_signature():
    """Removing the post-quantum half must be detectable, not a silent downgrade."""
    m = dict(_manifest())
    m.pop("countersignature", None)
    verdict = verify_engine_manifest(m, _keys())
    assert verdict["valid"] is False, "a record with no counter half was accepted"


def test_the_cli_verifies_the_example_end_to_end():
    """The exact command the README gives a counterparty."""
    result = CliRunner().invoke(main, ["verify-engine", str(EXAMPLE)])
    assert result.exit_code == 0, result.output
    assert _manifest()["sig_algorithm"] in result.output
    assert "VALID" in result.output


def test_the_cli_reports_the_engine_absent():
    """The independence claim, read from the machine rather than asserted in prose."""
    result = CliRunner().invoke(main, ["verify-engine", str(EXAMPLE), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["engine_absent"] is True, "the engine was importable, so this was not an absent-engine check"
    assert payload["signature"]["valid"] is True
    assert payload["anchor"]["valid"] is True
    assert payload["suite"] == _manifest()["sig_algorithm"]


def test_the_recorded_engine_verdict_agrees_with_this_verifier():
    """RECEIPT.txt records what the engine said. Both sides must still agree."""
    receipt = (EXAMPLE / "RECEIPT.txt").read_text(encoding="utf-8")
    assert "signature_valid=True composite=True" in receipt, "the engine verdict line moved or changed"
    verdict = verify_engine_manifest(_manifest(), _keys())
    assert verdict["valid"] is True
    assert verdict["composite"] is True


def test_the_receipt_names_the_batch_and_suite_the_manifest_declares():
    """Catches the example being regenerated without its receipt."""
    m = _manifest()
    receipt = (EXAMPLE / "RECEIPT.txt").read_text(encoding="utf-8")
    assert m["batch_id"] in receipt, f"RECEIPT.txt does not name batch {m['batch_id']}"
    assert m["sig_algorithm"] in receipt, f"RECEIPT.txt does not name suite {m['sig_algorithm']}"


def test_the_cli_fails_a_copied_example_with_a_tampered_manifest(tmp_path):
    """Tamper detection through the real command, not just the library."""
    copy = tmp_path / "engine-record"
    shutil.copytree(EXAMPLE, copy)
    manifest = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
    manifest["ledger_id"] = "not-the-ledger-that-was-signed"
    (copy / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = CliRunner().invoke(main, ["verify-engine", str(copy)])
    assert result.exit_code == 1, result.output


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
