# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""Tests for the pinned-JWKS provider assertion path (E3 independence)."""
from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from witnessos_verifier.corroboration import _jwt_identity
from witnessos_verifier.jwt_provider import (
    JwtError,
    appraise_assertion,
    load_jwks,
    verify_jwt,
)

ISSUER = "https://accounts.google.com"
AUDIENCE = "https://gateway.example.com/pubsub"
KID = "test-kid-1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return _b64url(raw)


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(rsa_key):
    numbers = rsa_key.public_key().public_numbers()
    return {
        KID: {
            "kty": "RSA",
            "kid": KID,
            "n": _int_b64url(numbers.n),
            "e": _int_b64url(numbers.e),
        }
    }


def make_token(rsa_key, *, claims=None, header=None, kid=KID, sign=True):
    now = int(time.time())
    body = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "provider-account@example.iam.gserviceaccount.com",
        "email": "provider-account@example.iam.gserviceaccount.com",
        "iat": now,
        "exp": now + 600,
    }
    if claims is not None:
        body = claims
    head = {"alg": "RS256", "typ": "JWT", "kid": kid}
    if header is not None:
        head = header
    signing_input = (
        f"{_b64url(json.dumps(head).encode())}."
        f"{_b64url(json.dumps(body).encode())}"
    )
    if sign:
        signature = rsa_key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
    else:
        signature = b"x" * 256
    return f"{signing_input}.{_b64url(signature)}"


def test_valid_token_verifies(jwks, rsa_key):
    claims = verify_jwt(make_token(rsa_key), jwks=jwks, issuer=ISSUER, audience=AUDIENCE)
    assert claims["iss"] == ISSUER
    assert claims["sub"].startswith("provider-account@")


def test_wrong_issuer_rejected(jwks, rsa_key):
    token = make_token(rsa_key)
    with pytest.raises(JwtError, match="iss"):
        verify_jwt(token, jwks=jwks, issuer="https://evil.example.com", audience=AUDIENCE)


def test_wrong_audience_rejected(jwks, rsa_key):
    with pytest.raises(JwtError, match="aud"):
        verify_jwt(make_token(rsa_key), jwks=jwks, issuer=ISSUER, audience="https://other")


def test_expired_rejected(jwks, rsa_key):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "provider-account",
        "iat": now - 7200,
        "exp": now - 3600,
    }
    with pytest.raises(JwtError, match="expired"):
        verify_jwt(make_token(rsa_key, claims=claims), jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_future_iat_rejected(jwks, rsa_key):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "provider-account",
        "iat": now + 7200,
        "exp": now + 10800,
    }
    with pytest.raises(JwtError, match="future"):
        verify_jwt(make_token(rsa_key, claims=claims), jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_tampered_payload_rejected(jwks, rsa_key):
    token = make_token(rsa_key)
    head, _, sig = token.split(".")
    forged_claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker", "exp": int(time.time()) + 600}
    forged = f"{head}.{_b64url(json.dumps(forged_claims).encode())}.{sig}"
    with pytest.raises(JwtError, match="signature"):
        verify_jwt(forged, jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_unsigned_token_rejected(jwks, rsa_key):
    with pytest.raises(JwtError, match="signature"):
        verify_jwt(make_token(rsa_key, sign=False), jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_alg_none_rejected(jwks, rsa_key):
    token = make_token(rsa_key, header={"alg": "none", "kid": KID})
    with pytest.raises(JwtError, match="alg"):
        verify_jwt(token, jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_hs256_confusion_rejected(jwks, rsa_key):
    """An HMAC token signed with the public key bytes must not be accepted."""
    token = make_token(rsa_key, header={"alg": "HS256", "kid": KID})
    with pytest.raises(JwtError, match="alg"):
        verify_jwt(token, jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_unknown_kid_rejected(jwks, rsa_key):
    token = make_token(rsa_key, kid="not-pinned")
    with pytest.raises(JwtError, match="kid"):
        verify_jwt(token, jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_missing_subject_rejected(jwks, rsa_key):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 600}
    with pytest.raises(JwtError, match="subject"):
        verify_jwt(make_token(rsa_key, claims=claims), jwks=jwks, issuer=ISSUER, audience=AUDIENCE)


def test_load_jwks_from_file(tmp_path, jwks):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": list(jwks.values())}))
    loaded = load_jwks(path)
    assert set(loaded) == {KID}


def test_load_jwks_without_keys_rejected(tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": []}))
    with pytest.raises(JwtError, match="no keys"):
        load_jwks(path)


def test_appraise_assertion_names_provider_and_subject(jwks, rsa_key):
    assertion = appraise_assertion(
        make_token(rsa_key),
        provider="google-pubsub",
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=jwks,
    )
    assert assertion.provider == "google-pubsub"
    assert assertion.subject.startswith("provider-account@")
    assert assertion.issued_at is not None


def _policy(tmp_path, jwks, **overrides):
    from witnessos_verifier.trust_policy import TrustPolicy

    jwks_path = tmp_path / "pinned-jwks.json"
    jwks_path.write_text(json.dumps({"keys": list(jwks.values())}))
    provider = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_path": str(jwks_path),
    }
    provider.update(overrides)
    data = {"provider_jwt_providers": {"google-pubsub": provider}}
    path = tmp_path / "trust-policy.json"
    path.write_text(json.dumps(data))
    return TrustPolicy.from_json(path)


def test_policy_parses_jwt_providers_observer_binding(tmp_path, jwks, rsa_key):
    policy = _policy(tmp_path, jwks)
    assert "google-pubsub" in policy.provider_jwt_providers
    assert policy.require_observer_identity is False
    identity = _jwt_identity(make_token(rsa_key), policy)
    assert identity == (
        "google-pubsub:provider-account@example.iam.gserviceaccount.com"
    )


def test_jwt_identity_rejects_wrong_audience(tmp_path, jwks, rsa_key):
    policy = _policy(tmp_path, jwks, audience="https://someone-else")
    assert _jwt_identity(make_token(rsa_key), policy) is None


def test_jwt_identity_without_providers_is_none(jwks, rsa_key):
    class Bare:
        provider_jwt_providers = {}

    assert _jwt_identity(make_token(rsa_key), Bare()) is None


def test_observer_binding_fields_parse(tmp_path):
    from witnessos_verifier.trust_policy import TrustPolicy

    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "observer_keys": {"ab" * 32: "Sovereign sensor, Brisbane"},
                "require_observer_identity": True,
            }
        )
    )
    policy = TrustPolicy.from_json(path)
    assert policy.require_observer_identity is True
    assert policy.observer_keys["ab" * 32].startswith("Sovereign sensor")
