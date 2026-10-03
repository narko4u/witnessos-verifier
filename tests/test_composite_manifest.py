"""3.13 step 2: composite signature suites on the batch manifest.

The property under test throughout: a suite this build cannot perform is a REFUSAL
naming the suite. It is never a skip and never a traceback.
"""
import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from witnessos_verifier.key_registry import KeyRecord, KeyRegistry
from witnessos_verifier.manifest import BatchManifest, verify_manifest

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
    HAVE_CRYPTO = True
except Exception:                                    # pragma: no cover
    HAVE_CRYPTO = False

requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")


def _raw(pub):
    try:
        return pub.public_bytes_raw()
    except AttributeError:
        from cryptography.hazmat.primitives import serialization
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _mk(algorithm):
    if algorithm == "Ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
    else:
        sk = mldsa.MLDSA65PrivateKey.generate()
    return sk, _raw(sk.public_key()).hex()


def _base(**over):
    d = {
        "batch_id": "b1", "signing_key_id": "key_primary", "case_id": "c1",
        "root": "aa" * 32, "prev_root": "bb" * 32, "event_ids": ["e1", "e2"],
        "start_seq": 1, "end_seq": 2, "signed_at": "2026-06-27T04:15:00Z",
    }
    d.update(over)
    return d


def _registry(p_pub, c_pub, p_alg="Ed25519", c_alg="ML-DSA-65"):
    reg = KeyRegistry()
    reg.add_key(KeyRecord("key_primary", p_pub, "active", p_alg))
    reg.add_key(KeyRecord("key_counter", c_pub, "active", c_alg))
    return reg


@requires_crypto
def _composite(tmp_path, suite="ed25519+ml-dsa-65", counter_id="key_counter", **over):
    """Write a valid composite manifest. Returns (path, registry)."""
    p_sk, p_pub = _mk("Ed25519")
    c_sk, c_pub = _mk("ML-DSA-65")
    d = _base(signature_suite=suite, countersigner_key_id=counter_id,
              countersignature="AA==", signature="AA==", **over)
    p = tmp_path / "m.json"
    p.write_text(json.dumps(d))
    m = BatchManifest.from_file(p)                    # to obtain signed_data
    d["signature"] = base64.b64encode(p_sk.sign(m.signed_data)).decode()
    d["countersignature"] = base64.b64encode(c_sk.sign(m.signed_data)).decode()
    p.write_text(json.dumps(d))
    return p, _registry(p_pub, c_pub)


# --- the version 1 path must not move -----------------------------------------

def test_v1_signed_data_is_byte_identical_to_the_old_formula(tmp_path):
    """The guardrail: the suite dimension must not change any existing record."""
    d = _base()
    p = tmp_path / "m.json"
    p.write_text(json.dumps(dict(d, signature="AA==")))
    m = BatchManifest.from_file(p)
    old_formula = json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert m.signed_data == old_formula
    assert m.is_composite is False
    assert m.suite_labels == []


@requires_crypto
def test_v1_manifest_still_verifies(tmp_path):
    sk, pub = _mk("Ed25519")
    d = _base()
    p = tmp_path / "m.json"
    p.write_text(json.dumps(dict(d, signature="AA==")))
    m = BatchManifest.from_file(p)
    d["signature"] = base64.b64encode(sk.sign(m.signed_data)).decode()
    p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), _registry(pub, "11" * 32))
    assert res.valid is True, res.errors
    assert res.signature_suite == ""


# --- the composite path -------------------------------------------------------

@requires_crypto
def test_composite_verifies_when_both_halves_are_valid(tmp_path):
    p, reg = _composite(tmp_path)
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is True, res.errors
    assert res.signature_suite == "ed25519+ml-dsa-65"
    assert res.countersignature_valid is True


@requires_crypto
def test_stripping_the_suite_breaks_the_primary_half(tmp_path):
    """The peeling attack. Removing the counter half and the declaration together
    must not leave a record that still verifies as a version 1 manifest."""
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text())
    for k in ("signature_suite", "countersigner_key_id", "countersignature"):
        d.pop(k)
    p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("invalid for scheme" in e for e in res.errors), res.errors


# --- the six refusals ---------------------------------------------------------

@requires_crypto
def test_refusal_1_suite_with_no_countersignature(tmp_path):
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text()); d.pop("countersignature"); p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("carries no countersignature" in e for e in res.errors)


@requires_crypto
def test_refusal_2_countersignature_with_no_suite(tmp_path):
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text()); d.pop("signature_suite"); p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("declares no signature suite" in e for e in res.errors)


@requires_crypto
def test_refusal_3_suite_naming_a_scheme_this_build_cannot_perform(tmp_path):
    """The whole point. Not a skip, a refusal that names the scheme."""
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text())
    d["signature_suite"] = "ed25519+ml-dsa-87"
    d["countersigner_key_id"] = "key_counter"
    p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("ml-dsa-87" in e.lower() for e in res.errors), res.errors


@requires_crypto
def test_refusal_4_suite_disagreeing_with_the_keys_declared_algorithms(tmp_path):
    """The swap. Both halves genuine, wrong scheme claimed."""
    p_sk, p_pub = _mk("Ed25519")
    c_sk, c_pub = _mk("ML-DSA-65")
    d = _base(signature_suite="ed25519+ml-dsa-65", countersigner_key_id="key_counter",
              countersignature="AA==", signature="AA==")
    p = tmp_path / "m.json"
    p.write_text(json.dumps(d))
    m = BatchManifest.from_file(p)
    d["signature"] = base64.b64encode(p_sk.sign(m.signed_data)).decode()
    d["countersignature"] = base64.b64encode(c_sk.sign(m.signed_data)).decode()
    p.write_text(json.dumps(d))
    # The counter key declares Ed25519 in the registry, so the suite no longer matches.
    reg = _registry(p_pub, c_pub, c_alg="Ed25519")
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("its keys declare" in e for e in res.errors), res.errors


@requires_crypto
def test_refusal_5_suite_with_no_countersigner_key(tmp_path):
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text()); d.pop("countersigner_key_id"); p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("names no countersigner key" in e for e in res.errors)


@requires_crypto
def test_refusal_6_a_half_that_does_not_verify(tmp_path):
    p, reg = _composite(tmp_path)
    d = json.loads(p.read_text())
    d["countersignature"] = base64.b64encode(b"\x00" * 3309).decode()
    p.write_text(json.dumps(d))
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("countersignature" in e for e in res.errors)


@requires_crypto
def test_a_one_scheme_suite_is_refused(tmp_path):
    p, reg = _composite(tmp_path, suite="ed25519")
    res = verify_manifest(BatchManifest.from_file(p), reg)
    assert res.valid is False
    assert any("fewer than two schemes" in e for e in res.errors)


# --- the CLI hole ------------------------------------------------------------

def test_cli_does_not_traceback_on_an_unperformable_suite(tmp_path, bundle_path):
    """An exit-code assertion alone would pass on a traceback. So assert no traceback.

    The library test above proves the reason is NAMED. This proves the CLI turns it
    into a verdict rather than crashing, which is the difference between a finding
    and a broken tool.
    """
    exe = Path(__file__).parent.parent / ".venv" / "bin" / "witnessos-verifier"
    if not exe.exists():
        pytest.skip("CLI not installed; run uv sync --extra dev")
    b = tmp_path / "bundle"
    shutil.copytree(bundle_path, b)
    mp = b / "batch_manifest.json"
    d = json.loads(mp.read_text())
    d["signature_suite"] = "ed25519+ml-dsa-87"
    d["countersigner_key_id"] = "key_counter"
    d["countersignature"] = "AA=="
    mp.write_text(json.dumps(d))
    r = subprocess.run([str(exe), "verify", str(b)], capture_output=True, text=True, timeout=30)
    out = r.stdout + r.stderr
    assert "Traceback" not in out, f"the CLI crashed instead of refusing:\n{out}"
    assert r.returncode != 0, out
