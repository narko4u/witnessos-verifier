"""3.13: the verifier performs a declared scheme instead of refusing all but Ed25519."""
import base64

import pytest

from witnessos_verifier.signatures import (
    UnsupportedScheme,
    verify_detached_signature,
    verify_signature,
)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
    HAVE_CRYPTO = True
except Exception as _exc:                            # pragma: no cover
    HAVE_CRYPTO = False

requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")
MSG = b'{"a":1}'


def _raw(pub):
    try:
        return pub.public_bytes_raw()
    except AttributeError:
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# --- the classical path must be untouched -------------------------------------

@requires_crypto
def test_ed25519_through_the_dispatch_matches_the_old_path():
    sk = ed25519.Ed25519PrivateKey.generate()
    raw = _raw(sk.public_key())
    sig = base64.b64encode(sk.sign(MSG)).decode()
    assert verify_signature("Ed25519", raw.hex(), MSG, sig) is True
    assert verify_detached_signature(raw.hex(), MSG, sig) is True


def test_absent_algorithm_is_read_as_ed25519():
    """An unlabelled record keeps its old meaning. Guardrail: no behaviour change."""
    assert verify_signature("", "00" * 32, MSG, base64.b64encode(b"x" * 64).decode()) is False


# --- the new scheme -----------------------------------------------------------

@requires_crypto
def test_ml_dsa_65_verifies_a_real_signature():
    sk = mldsa.MLDSA65PrivateKey.generate()
    raw = _raw(sk.public_key())
    sig = base64.b64encode(sk.sign(MSG)).decode()
    assert verify_signature("ML-DSA-65", raw.hex(), MSG, sig) is True
    assert verify_signature("ml-dsa-65", raw.hex(), MSG, sig) is True


@requires_crypto
def test_ml_dsa_65_rejects_a_tampered_message():
    sk = mldsa.MLDSA65PrivateKey.generate()
    raw = _raw(sk.public_key())
    sig = base64.b64encode(sk.sign(MSG)).decode()
    assert verify_signature("ML-DSA-65", raw.hex(), b'{"a":2}', sig) is False


@requires_crypto
def test_a_signature_from_another_scheme_is_not_accepted():
    """A classical signature cannot pass as post-quantum."""
    sk = ed25519.Ed25519PrivateKey.generate()
    sig = base64.b64encode(sk.sign(MSG)).decode()
    assert verify_signature("ML-DSA-65", _raw(sk.public_key()).hex(), MSG, sig) is False


# --- the refusals that must survive ------------------------------------------

def test_an_unknown_scheme_refuses_by_name():
    with pytest.raises(UnsupportedScheme) as e:
        verify_signature("Falcon-512", "00" * 32, MSG, base64.b64encode(b"x").decode())
    assert "Falcon-512" in str(e.value)


def test_an_unperformable_suite_never_falls_back_to_a_pass():
    """The whole point: cannot-perform must raise, never return True."""
    for scheme in ("RSA-2048", "Ed448", "", "  "):
        if scheme.strip() == "":
            continue
        with pytest.raises(UnsupportedScheme):
            verify_signature(scheme, "00" * 32, MSG, base64.b64encode(b"x").decode())


# --- every parameter set the engine can register ------------------------------

@pytest.mark.parametrize(
    "declared,key_class",
    [
        ("ML-DSA-44", "MLDSA44PrivateKey"),
        ("ML-DSA-65", "MLDSA65PrivateKey"),
        ("ML-DSA-87", "MLDSA87PrivateKey"),
        ("ml_dsa_44", "MLDSA44PrivateKey"),
        ("mldsa87", "MLDSA87PrivateKey"),
    ],
)
@requires_crypto
def test_each_ml_dsa_parameter_set_verifies(declared, key_class):
    """The engine registers 44, 65 or 87 by deployment key, so all three must perform."""
    private = getattr(mldsa, key_class).generate()
    raw = _raw(private.public_key())
    signature = base64.b64encode(private.sign(MSG)).decode()

    assert verify_signature(declared, raw.hex(), MSG, signature) is True


@requires_crypto
def test_a_signature_from_a_different_parameter_set_is_refused_not_unsupported():
    """Same family, wrong key length: a bad signature, not a missing capability."""
    private_65 = mldsa.MLDSA65PrivateKey.generate()
    private_44 = mldsa.MLDSA44PrivateKey.generate()
    signature = base64.b64encode(private_44.sign(MSG)).decode()

    assert verify_signature("ML-DSA-65", _raw(private_65.public_key()).hex(), MSG, signature) is False


@requires_crypto
def test_a_hybrid_suite_may_declare_any_parameter_set():
    """The composite path splits labels, so a hybrid half at 44 or 87 dispatches the same way."""
    classical = ed25519.Ed25519PrivateKey.generate()
    pq = mldsa.MLDSA87PrivateKey.generate()
    ed_sig = base64.b64encode(classical.sign(MSG)).decode()
    pq_sig = base64.b64encode(pq.sign(MSG)).decode()

    assert verify_signature("ed25519", _raw(classical.public_key()).hex(), MSG, ed_sig) is True
    assert verify_signature("ml-dsa-87", _raw(pq.public_key()).hex(), MSG, pq_sig) is True


@requires_crypto
def test_an_unknown_scheme_still_refuses_by_name():
    with pytest.raises(UnsupportedScheme):
        verify_signature("ml-dsa-99", "00", MSG, "AA==")
