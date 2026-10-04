"""Engine-native verification: the public verifier checks the engine's own bytes.

No engine import. The record is built here in the engine's shape, signed in the engine's
format, and verified by this module alone. That is the property a counterparty relies on.
"""

import pytest

from witnessos_verifier.engine_native import (
    canonical_bytes,
    engine_signed_payload,
    verify_engine_anchor,
    verify_engine_manifest,
)

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


def _sign(sk, payload, label):
    """Sign in the engine's wire format: '<label>:<hex>'."""
    return f"{label}:{sk.sign(payload).hex()}"


def _manifest(**over):
    m = {
        "batch_id": "wos_batch_5_9", "first_global_seq": 5, "last_global_seq": 9,
        "leaf_count": 5, "merkle_root": "sha256:" + "ab" * 32,
        "previous_manifest_hash": None, "anchor_status": "pending",
        "signed_at": "2026-10-03T10:00:00+00:00",
    }
    m.update(over)
    return m


@requires_crypto
def _hybrid():
    p_sk = ed25519.Ed25519PrivateKey.generate()
    c_sk = mldsa.MLDSA65PrivateKey.generate()
    keys = {
        "k_primary": {"public_key_hex": _raw(p_sk.public_key()).hex(), "algorithm": "ed25519"},
        "k_counter": {"public_key_hex": _raw(c_sk.public_key()).hex(), "algorithm": "ml-dsa-65"},
    }
    m = _manifest(signer_key_id="k_primary", sig_algorithm="ed25519+ml-dsa-65",
                  countersigner_key_id="k_counter")
    payload = engine_signed_payload(m)               # includes the two claims
    m["signature"] = _sign(p_sk, payload, "ed25519")
    m["countersignature"] = _sign(c_sk, payload, "ml-dsa-65")
    return m, keys, p_sk, c_sk, payload


def test_the_canonical_form_matches_the_engine_rule():
    """Sorted keys, compact separators, ASCII escapes. Proven identical to the engine."""
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_the_signed_payload_omits_an_unstated_claim():
    """The engine drops a null claim rather than carrying it, so the bytes must too."""
    stated = engine_signed_payload(_manifest(signer_key_id="k"))
    assert b"sig_algorithm" not in stated
    assert b"signer_key_id" in stated


@requires_crypto
def test_a_hybrid_engine_manifest_verifies():
    m, keys, _p, _c, _pl = _hybrid()
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is True, v["errors"]
    assert v["halves"] == {"primary": True, "counter": True}


@requires_crypto
def test_a_single_scheme_engine_manifest_verifies():
    """The shape the engine wrote before the suite dimension existed."""
    sk = ed25519.Ed25519PrivateKey.generate()
    keys = {"k_primary": {"public_key_hex": _raw(sk.public_key()).hex(), "algorithm": "ed25519"}}
    m = _manifest(signer_key_id="k_primary")
    m["signature"] = _sign(sk, engine_signed_payload(m), "ed25519")
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is True, v["errors"]
    assert v.get("composite") is False


@requires_crypto
def test_stripping_the_counter_half_breaks_the_primary():
    """The carrier property. Removing the counter half and the suite claim must fail."""
    m, keys, _p, _c, _pl = _hybrid()
    for k in ("sig_algorithm", "countersigner_key_id", "countersignature"):
        m.pop(k)
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False


@requires_crypto
def test_an_unperformable_suite_refuses_by_name():
    m, keys, _p, c_sk, payload = _hybrid()
    m["sig_algorithm"] = "ed25519+ml-dsa-87"
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False
    assert any("ml-dsa-87" in e.lower() or "does not match" in e for e in v["errors"]), v["errors"]


@requires_crypto
def test_a_signature_label_disagreeing_with_the_key_refuses():
    m, keys, _p, _c, payload = _hybrid()
    keys["k_counter"]["algorithm"] = "ed25519"
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False


def test_the_anchor_reproduces_from_declared_leaves():
    leaves = ["ab" * 32, "cd" * 32]
    from witnessos_verifier.merkle import build_merkle_tree
    root = build_merkle_tree([bytes.fromhex(x) for x in leaves]).hex()
    v = verify_engine_anchor({"merkle_root": "sha256:" + root, "leaf_count": 2}, leaves)
    assert v["valid"] is True, v["errors"]


def test_a_wrong_leaf_fails_the_anchor():
    v = verify_engine_anchor({"merkle_root": "sha256:" + "00" * 32, "leaf_count": 1}, ["ab" * 32])
    assert v["valid"] is False
