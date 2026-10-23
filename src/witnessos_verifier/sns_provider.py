# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""AWS SNS message signatures: a provider key we never hold.

E3 needs a party other than the deployment whose identity the operator can
establish, speaking to the outcome, with the binding fields inside the signed
bytes. A provider that shares a secret with us fails the first test. A provider
that only vouches for identity fails the third.

SNS fits because AWS signs the whole Message string, so the binding object we
put in it is covered by a signature made with a key only AWS holds. The signing
certificate is fetched by AWS from its own domain, and here it is pinned to a
file the operator provisioned, so no verification step reaches the network.

Supported: SignatureVersion 1 (RSA-SHA1) and 2 (RSA-SHA256). SNS string-to-sign
is the same shape for both; only the digest differs. Anything else fails closed.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGNED_FIELDS = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
ALLOWED_CERT_HOSTS = (".amazonaws.com",)
ALLOWED_CERT_SUFFIXES = ("/SimpleNotificationService-", "/sns-")


class SnsError(Exception):
    """The message is not a valid, current, correctly-signed SNS notification."""


def string_to_sign(message: Mapping[str, Any]) -> bytes:
    parts = []
    for field in SIGNED_FIELDS:
        value = message.get(field)
        if value is None:
            if field == "Subject":
                value = ""
            else:
                raise SnsError(f"SNS message is missing {field}")
        parts.append(f"{field}\n{value}\n")
    return "".join(parts).encode("utf-8")


def _digest(version: str):
    if version == "1":
        return hashes.SHA1()
    if version == "2":
        return hashes.SHA256()
    raise SnsError(f"unsupported SNS SignatureVersion {version!r}")


def load_certificate(path) -> rsa.RSAPublicKey:
    with open(path, "rb") as handle:
        cert = x509.load_pem_x509_certificate(handle.read())
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise SnsError("pinned SNS certificate is not RSA")
    return key


def verify_message(
    message: Mapping[str, Any],
    *,
    cert_path,
    allowed_topic_arn: Optional[str] = None,
) -> dict:
    """Verify an SNS notification against a pinned certificate.

    Returns the parsed Message when it is a JSON object, so the caller can read
    the binding fields the signature actually covers. Raises SnsError otherwise.
    """
    if not isinstance(message, Mapping):
        raise SnsError("SNS message is not an object")
    if message.get("Type") != "Notification":
        raise SnsError(f"SNS Type is {message.get('Type')!r}, expected 'Notification'")

    topic = message.get("TopicArn")
    if allowed_topic_arn is not None and topic != allowed_topic_arn:
        raise SnsError(f"SNS TopicArn {topic!r} is not the pinned topic")

    cert_url = str(message.get("SigningCertURL") or "")
    if cert_url:
        parsed = urlparse(cert_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SnsError("SigningCertURL is not https")
        host = parsed.hostname.lower()
        if not any(host.endswith(suffix) for suffix in ALLOWED_CERT_HOSTS):
            raise SnsError(f"SigningCertURL host {host!r} is not an AWS host")
    # The URL is checked for shape only. Verification uses the pinned file, so a
    # substituted URL cannot change which key we trust.

    version = str(message.get("SignatureVersion") or "")
    signature_b64 = message.get("Signature")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise SnsError("SNS message has no Signature")

    key = load_certificate(cert_path)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SnsError(f"SNS Signature is not base64: {exc}") from exc

    try:
        key.verify(signature, string_to_sign(message), padding.PKCS1v15(), _digest(version))
    except InvalidSignature as exc:
        raise SnsError("SNS signature does not verify over the signed fields") from exc

    raw = message.get("Message")
    if not isinstance(raw, str):
        raise SnsError("SNS Message is not a string")
    import json

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SnsError(f"SNS Message is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SnsError("SNS Message JSON is not an object")
    return parsed


@dataclass(frozen=True)
class SnsAssertion:
    """The binding object AWS signed, and the topic that carried it."""

    topic_arn: str
    message_id: str
    timestamp: str
    binding: Mapping[str, Any]


def appraise(
    message: Mapping[str, Any], *, cert_path, allowed_topic_arn: Optional[str] = None
) -> SnsAssertion:
    binding = verify_message(
        message, cert_path=cert_path, allowed_topic_arn=allowed_topic_arn
    )
    return SnsAssertion(
        topic_arn=str(message.get("TopicArn")),
        message_id=str(message.get("MessageId")),
        timestamp=str(message.get("Timestamp")),
        binding=binding,
    )
