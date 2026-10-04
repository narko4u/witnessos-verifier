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

# ── The labelled single-scheme shape ───────────────────────────────────────
# These cover the form the engine writes TODAY: `sig_algorithm` is set to the
# primary label when exactly one ledger key is provisioned. It is distinct from
# the `sig_algorithm is None` shape above, which is what the engine wrote before
# the suite dimension existed.
#
# The gap: the None case had a single-scheme branch and the labelled case did
# not, so a labelled single-scheme manifest fell through to the composite branch
# and was refused for naming fewer than two schemes. Every classical record the
# engine still produces failed verification while its signature checked out.
# Found by an end-to-end run on 2026-10-04, not by a unit test.


def _single(algorithm, label):
    """One key, one label, signed the way the engine signs it."""
    if algorithm == "ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
    else:
        sk = mldsa.MLDSA65PrivateKey.generate()
    keys = {"k_one": {"public_key_hex": _raw(sk.public_key()).hex(), "algorithm": algorithm}}
    m = _manifest(signer_key_id="k_one", sig_algorithm=label)
    payload = engine_signed_payload(m)
    m["signature"] = _sign(sk, payload, label)
    return m, keys


@requires_crypto
def test_a_labelled_classical_manifest_verifies():
    """Ed25519 alone, labelled. The default deployment."""
    m, keys = _single("ed25519", "ed25519")
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is True, v["errors"]
    assert v["composite"] is False
    assert v["suite"] == "ed25519"


@requires_crypto
def test_a_labelled_post_quantum_manifest_verifies():
    """ML-DSA-65 alone, labelled. The post-quantum profile with nothing classical."""
    m, keys = _single("ml-dsa-65", "ml-dsa-65")
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is True, v["errors"]
    assert v["composite"] is False


@requires_crypto
def test_a_tampered_labelled_single_scheme_manifest_fails():
    """The control. The same record with one signature nibble flipped."""
    m, keys = _single("ed25519", "ed25519")
    label, hexpart = m["signature"].split(":", 1)
    flipped = ("1" if hexpart[0] == "0" else "0") + hexpart[1:]
    m["signature"] = f"{label}:{flipped}"
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False
    assert v["halves"]["primary"] is False


@requires_crypto
def test_a_single_label_disagreeing_with_its_key_is_rejected():
    """A label naming a scheme the key does not declare is still refused."""
    m, keys = _single("ed25519", "ed25519")
    m["sig_algorithm"] = "ml-dsa-65"
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False
    assert any("does not match the key's declared scheme" in e for e in v["errors"]), v["errors"]


@requires_crypto
def test_a_composite_suite_missing_its_second_half_is_still_rejected():
    """Single-scheme is allowed; a TWO-scheme claim with no countersignature is not."""
    m, keys = _single("ed25519", "ed25519+ml-dsa-65")
    v = verify_engine_manifest(m, keys)
    assert v["valid"] is False
    assert any("no countersignature is present" in e for e in v["errors"]), v["errors"]
