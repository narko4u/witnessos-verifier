# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""AWS SNS signature verification against a pinned certificate."""
from __future__ import annotations

import base64
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from witnessos_verifier.sns_provider import (
    SnsError,
    appraise,
    string_to_sign,
    verify_message,
)

TOPIC = "arn:aws:sns:ap-southeast-2:123456789012:witnessos-outcomes"


@pytest.fixture(scope="module")
def key_and_cert(tmp_path_factory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("sns") / "sns.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, path


def make_message(key, *, version="2", overrides=None):
    binding = {
        "case_id": "case-123",
        "action_event_id": "evt-9",
        "outcome": "delivered",
        "provider_record_id": "gmail-msg-778",
        "provider_record_digest": "ab" * 32,
    }
    message = {
        "Type": "Notification",
        "MessageId": "msg-1",
        "TopicArn": TOPIC,
        "Subject": None,
        "Timestamp": "2026-10-23T09:00:00.000Z",
        "Message": json.dumps(binding),
        "SignatureVersion": version,
        "SigningCertURL": (
            "https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-abc.pem"
        ),
    }
    if overrides:
        message.update(overrides)
    digest = hashes.SHA1() if version == "1" else hashes.SHA256()
    signature = key.sign(string_to_sign(message), padding.PKCS1v15(), digest)
    message["Signature"] = base64.b64encode(signature).decode()
    return message, binding


def test_valid_v2_message_verifies(key_and_cert):
    key, cert = key_and_cert
    message, binding = make_message(key)
    parsed = verify_message(message, cert_path=cert, allowed_topic_arn=TOPIC)
    assert parsed["provider_record_id"] == binding["provider_record_id"]


def test_valid_v1_message_verifies(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key, version="1")
    assert verify_message(message, cert_path=cert)["case_id"] == "case-123"


def test_tampered_message_rejected(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key)
    message["Message"] = json.dumps({"case_id": "other-case"})
    with pytest.raises(SnsError, match="signature does not verify"):
        verify_message(message, cert_path=cert)


def test_wrong_topic_rejected(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key)
    with pytest.raises(SnsError, match="TopicArn"):
        verify_message(message, cert_path=cert, allowed_topic_arn="arn:aws:sns:ap-southeast-2:1:other")


def test_unsupported_signature_version_rejected(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key)
    message["SignatureVersion"] = "3"
    with pytest.raises(SnsError, match="SignatureVersion"):
        verify_message(message, cert_path=cert)


def test_non_notification_type_rejected(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key, overrides={"Type": "SubscriptionConfirmation"})
    with pytest.raises(SnsError, match="Type"):
        verify_message(message, cert_path=cert)


def test_non_aws_cert_url_rejected(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(
        key, overrides={"SigningCertURL": "https://evil.example.com/cert.pem"}
    )
    with pytest.raises(SnsError, match="not an AWS host"):
        verify_message(message, cert_path=cert)


def test_message_must_be_json(key_and_cert):
    key, cert = key_and_cert
    message, _ = make_message(key, overrides={"Message": "not json"})
    key.sign  # signature recomputed below for the new body
    signature = key.sign(string_to_sign(message), padding.PKCS1v15(), hashes.SHA256())
    message["Signature"] = base64.b64encode(signature).decode()
    with pytest.raises(SnsError, match="not JSON"):
        verify_message(message, cert_path=cert)


def test_appraise_returns_binding_and_topic(key_and_cert):
    key, cert = key_and_cert
    message, binding = make_message(key)
    assertion = appraise(message, cert_path=cert, allowed_topic_arn=TOPIC)
    assert assertion.topic_arn == TOPIC
    assert dict(assertion.binding) == binding


def _event(case_id="case-123"):
    from types import SimpleNamespace

    return SimpleNamespace(case_id=case_id)


def _policy(cert):
    from types import SimpleNamespace

    return SimpleNamespace(
        sns_providers={
            "aws-sns": {"cert_path": str(cert), "topic_arn": TOPIC},
        }
    )


def test_sns_identity_accepts_matching_binding(key_and_cert):
    from witnessos_verifier.corroboration import _sns_identity

    key, cert = key_and_cert
    message, binding = make_message(key)
    payload = {
        "provider_record_id": binding["provider_record_id"],
        "provider_record_digest": binding["provider_record_digest"],
        "outcome": binding["outcome"],
    }
    identity = _sns_identity(message, _policy(cert), _event(), payload)
    assert identity == f"aws-sns:{TOPIC}"


def test_sns_identity_rejects_other_case(key_and_cert):
    from witnessos_verifier.corroboration import _sns_identity

    key, cert = key_and_cert
    message, _ = make_message(key)
    assert _sns_identity(message, _policy(cert), _event("case-999"), {}) is None


def test_sns_identity_rejects_disagreeing_record(key_and_cert):
    from witnessos_verifier.corroboration import _sns_identity

    key, cert = key_and_cert
    message, _ = make_message(key)
    payload = {"provider_record_id": "some-other-record"}
    assert _sns_identity(message, _policy(cert), _event(), payload) is None
