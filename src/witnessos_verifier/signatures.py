# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Ed25519 signature verification for WitnessOS evidence.

Verifies detached Ed25519 signatures against canonical event data.
Uses PyNaCl for Ed25519 operations.
"""

import base64
from typing import Dict

import nacl.exceptions
import nacl.signing


class SignatureError(Exception):
    """Signature verification error."""


class KeyStatus:
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"

    @classmethod
    def valid_statuses(cls) -> set:
        return {cls.ACTIVE}


def verify_detached_signature(
    public_key_hex: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Verify a detached Ed25519 signature.

    Args:
        public_key_hex: Ed25519 public key as hex string (64 hex chars = 32 bytes)
        message: The message that was signed (canonical bytes)
        signature_b64: Base64-encoded Ed25519 signature

    Returns:
        True if the signature is valid.
    """
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = base64.b64decode(signature_b64, validate=True)
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(message, signature_bytes)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


class UnsupportedScheme(Exception):
    """A declared scheme this build cannot perform.

    Raised rather than returned as False, so a caller refuses by name instead of
    reporting a bad signature. A verifier that cannot perform a declared suite
    must not be able to downgrade the record to the half it can perform.
    """


# Canonical scheme labels, matched case-insensitively. Unknown labels refuse.
_ED25519_LABELS = {"ed25519"}
_ML_DSA_65_LABELS = {"ml-dsa-65", "ml_dsa_65", "mldsa65"}


def verify_signature(
    algorithm: str,
    public_key_hex: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Verify one detached signature under the declared scheme.

    Args:
        algorithm: the scheme the record declares. Empty or absent means Ed25519.
        public_key_hex: raw public key bytes as hex.
        message: the canonical bytes that were signed.
        signature_b64: base64 signature.

    Returns:
        True only when the signature verifies under that scheme.

    Raises:
        UnsupportedScheme: the declared scheme cannot be performed here. Callers
            must turn this into a refusal, never into a pass.
    """
    label = (algorithm or "Ed25519").strip()
    key = label.lower()
    if key in _ED25519_LABELS:
        return verify_detached_signature(public_key_hex, message, signature_b64)
    if key in _ML_DSA_65_LABELS:
        return _verify_ml_dsa_65(public_key_hex, message, signature_b64)
    raise UnsupportedScheme(label)


def _verify_ml_dsa_65(
    public_key_hex: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """ML-DSA-65 verification (FIPS 204).

    The post-quantum backend is an optional dependency. When it is absent this
    raises UnsupportedScheme, so a record declaring a suite is refused rather
    than quietly accepted as a single-scheme record.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:
        raise UnsupportedScheme("ML-DSA-65: backend not installed") from exc
    try:
        public_key = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(base64.b64decode(signature_b64, validate=True), message)
        return True
    except Exception:
        return False


def verify_signed_field(
    event_data: dict,
    signature_key: str = "signed",
) -> Dict[str, str]:
    """Verify the 'signed' field of an event.

    The 'signed' field contains a copy of the headers + payload that was
    signed. This function verifies the canonical bytes match.

    Returns:
        Dict with 'status': 'ok' or 'mismatch', and details.
    """
    raise NotImplementedError("Full signed-field verification requires event context")
