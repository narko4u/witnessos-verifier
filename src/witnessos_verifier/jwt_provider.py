# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""Independent provider identity assertions, verified offline.

The E3 rung turns on a party other than the deployment confirming the outcome.
A provider that only shares a secret with us (an HMAC webhook signature) does not
qualify: we hold the same secret, so the record proves transport and nothing
about who else saw the outcome.

A provider that signs with a key it publishes, and never gives us the private
half, does qualify. This module verifies that assertion:

  - the token is a compact JWS with alg RS256, signed by the key named by `kid`
  - the key comes from a JWKS we pinned, which the provider publishes
  - `iss` and `aud` match what the operator declared for that provider
  - `exp` has not passed and `iat` is not in the future beyond a small leeway
  - a subject claim is present, so the assertion names a party

Nothing here reaches the network. A verifier that fetches keys at verification
time can be steered by whoever controls the network, so the JWKS is a pinned
file and a stale one fails closed.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALG = "RS256"
DEFAULT_LEEWAY = 300


class JwtError(Exception):
    """The token is not a valid, current, correctly-issued assertion."""


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise JwtError("empty JWT segment")
    padding_needed = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding_needed)
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same answer
        raise JwtError(f"JWT segment is not base64url: {exc}") from exc


def _int_from_b64url(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def load_jwks(path) -> Dict[str, Any]:
    """Load a pinned JWKS file and return it keyed by kid.

    Accepts either a bare JWKS ({"keys": [...]}) or Google's certificate list
    ({"keys": [{"kid": ..., "n": ..., "e": ...}]}), which is the same shape.
    """
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list) or not keys:
        raise JwtError("JWKS has no keys")
    out: Dict[str, Any] = {}
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        if not kid:
            continue
        out[kid] = entry
    if not out:
        raise JwtError("JWKS has no usable kid entries")
    return out


def _public_key(entry: Mapping[str, Any]) -> rsa.RSAPublicKey:
    kty = entry.get("kty")
    if kty != "RSA":
        raise JwtError(f"JWKS key is {kty!r}, not RSA")
    try:
        n = _int_from_b64url(entry["n"])
        e = _int_from_b64url(entry["e"])
    except KeyError as exc:
        raise JwtError(f"JWKS key is missing {exc.args[0]}") from exc
    return rsa.RSAPublicNumbers(e, n).public_key()


def verify_jwt(
    token: str,
    *,
    jwks: Mapping[str, Any],
    issuer: str,
    audience: str,
    now: Optional[float] = None,
    leeway: int = DEFAULT_LEEWAY,
    require_subject: bool = True,
) -> Dict[str, Any]:
    """Verify a compact RS256 JWS against a pinned JWKS and return its claims.

    Raises JwtError on anything that is not provably good. Callers must not
    treat a partially valid token as corroboration.
    """
    if not isinstance(token, str):
        raise JwtError("token is not a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("token is not a compact JWS")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except json.JSONDecodeError as exc:
        raise JwtError(f"token header or payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JwtError("token header or payload is not an object")

    if header.get("alg") != ALG:
        raise JwtError(f"token alg is {header.get('alg')!r}, expected {ALG}")
    kid = header.get("kid")
    if not kid:
        raise JwtError("token header has no kid")
    entry = jwks.get(kid)
    if entry is None:
        raise JwtError(f"token kid {kid!r} is not in the pinned JWKS")

    key = _public_key(entry)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(signature_b64)
    try:
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise JwtError("token signature does not verify") from exc

    current = time.time() if now is None else float(now)

    if claims.get("iss") != issuer:
        raise JwtError(f"token iss {claims.get('iss')!r} is not {issuer!r}")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if audience not in audiences:
        raise JwtError(f"token aud {aud!r} does not include {audience!r}")

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise JwtError("token has no exp")
    if current > float(exp) + leeway:
        raise JwtError("token has expired")

    iat = claims.get("iat")
    if iat is not None and not isinstance(iat, (int, float)):
        raise JwtError("token iat is not a number")
    if isinstance(iat, (int, float)) and float(iat) > current + leeway:
        raise JwtError("token is issued in the future")

    if require_subject:
        subject = claims.get("sub") or claims.get("email")
        if not subject or not isinstance(subject, str):
            raise JwtError("token names no subject")

    return claims


@dataclass(frozen=True)
class ProviderAssertion:
    """What an independent provider asserted, and which declared provider it is."""

    provider: str
    subject: str
    issuer: str
    issued_at: Optional[int]
    claims: Mapping[str, Any]


def appraise_assertion(
    token: str,
    *,
    provider: str,
    issuer: str,
    audience: str,
    jwks: Mapping[str, Any],
    now: Optional[float] = None,
) -> ProviderAssertion:
    claims = verify_jwt(
        token, jwks=jwks, issuer=issuer, audience=audience, now=now
    )
    subject = claims.get("sub") or claims.get("email")
    issued_at = claims.get("iat")
    return ProviderAssertion(
        provider=provider,
        subject=str(subject),
        issuer=issuer,
        issued_at=int(issued_at) if isinstance(issued_at, (int, float)) else None,
        claims=claims,
    )
