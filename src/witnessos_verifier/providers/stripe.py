"""Stripe, as a verifier-performed state probe.

Stripe does not sign API responses. A bundle therefore cannot carry Stripe's
authentication, no matter what a webhook handler recorded, and an HMAC webhook
signature is a shared secret rather than an independent check. What a verifier can
do is ask Stripe itself, over TLS, with its own credentials, at verification time.
That is the route implemented here, and it is why this adapter is a
``VERIFIER_STATE_PROBE`` rather than a signature route.

Three consequences, stated because they are the difference between this and a
producer claiming corroboration:

* the probe happens in ``fetch_or_verify_record``, at verification time, from the
  verifier's own credentials. A record whose ``source`` is ``bundle`` is refused by
  the contract in ``base``;
* the digest compared is of the bytes this adapter received, so a producer cannot
  predict or pre-compute it;
* ``livemode`` is checked against the verifier's own expectation, so a test-mode
  object cannot stand in for a live one.

Provisioning: ``STRIPE_API_KEY`` in the verifier's environment (read-only key is
enough) and ``STRIPE_EXPECTED_LIVEMODE`` of ``live`` or ``test``. Absent either, the
adapter answers that it cannot authenticate the provider, and the case caps at E2.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, Optional, Sequence

from .base import (
    ProviderCorroborationAdapter,
    ProviderIdentity,
    ProviderRecord,
    ProviderTransport,
    TrustRoute,
    register_adapter,
)

API_BASE = "https://api.stripe.com/v1"

# Stripe object-id prefixes the adapter knows how to look up.
OBJECT_PATHS = {
    "pi_": "payment_intents",
    "re_": "refunds",
    "ch_": "charges",
    "py_": "payment_intents",
}

CASE_FIELD = "witnessos_case_id"
ACTION_FIELD = "witnessos_action_event_id"
SUBJECT_FIELD = "witnessos_subject_digest"
SIGNER_FIELD = "witnessos_signer_key"


class UrllibTransport(ProviderTransport):
    """The real transport. TLS verification is on and cannot be turned off here."""

    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def get_json(self, url: str, headers: Dict[str, str]):
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            try:
                return error.code, json.loads(body)
            except ValueError:
                return error.code, {"error": {"message": body[:200]}}


@register_adapter
class StripeStateProbeAdapter(ProviderCorroborationAdapter):
    provider_id = "stripe"
    route = TrustRoute.VERIFIER_STATE_PROBE

    def _key(self) -> Optional[str]:
        return os.environ.get("STRIPE_API_KEY") or None

    def _expected_livemode(self) -> Optional[bool]:
        raw = (os.environ.get("STRIPE_EXPECTED_LIVEMODE") or "").strip().lower()
        if raw in {"live", "true", "1"}:
            return True
        if raw in {"test", "false", "0"}:
            return False
        return None

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._key()}", "Accept": "application/json"}

    def authenticate_provider(self) -> Optional[ProviderIdentity]:
        if self.transport is None or not self._key():
            return None
        status, body = self.transport.get_json(f"{API_BASE}/account", self._headers())
        if status != 200 or not isinstance(body, dict) or not body.get("id"):
            return None
        return ProviderIdentity(
            provider_id=self.provider_id,
            route=self.route,
            account_id=str(body["id"]),
            basis="https api.stripe.com /v1/account with the verifier's own credentials",
            authenticated=True,
        )

    def fetch_or_verify_record(self, record_id: str) -> Optional[ProviderRecord]:
        if self.transport is None:
            return None
        # Accept either a bare id or "payment_intent:pi_123"; the bare form is
        # resolved by prefix so a caller cannot choose the endpoint freely.
        object_type, _, identifier = record_id.rpartition(":")
        if not identifier:
            identifier = record_id
            object_type = ""
        prefix = identifier[:3]
        path = OBJECT_PATHS.get(prefix)
        if path is None:
            return None
        if object_type and object_type not in {path, path.rstrip("s")}:
            return None

        status, body = self.transport.get_json(f"{API_BASE}/{path}/{identifier}", self._headers())
        if status != 200 or not isinstance(body, dict):
            return None
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return ProviderRecord(
            provider_id=self.provider_id,
            record_id=str(body.get("id") or identifier),
            digest=hashlib.sha256(canonical).hexdigest(),
            body=body,
            source="verifier_probe",
        )

    def verify_record_signature_or_trust_route(
        self, record: ProviderRecord, identity: ProviderIdentity
    ) -> bool:
        # There is no signature to check; the trust route is the probe itself, and
        # the probe is only meaningful if the object belongs to the account the
        # verifier authenticated and matches the mode the verifier expects.
        expected = self._expected_livemode()
        if expected is None:
            return False
        if bool(record.body.get("livemode")) is not expected:
            return False
        account = record.body.get("account")
        if isinstance(account, str) and identity.account_id and account != identity.account_id:
            return False
        return record.source == "verifier_probe"

    def _metadata(self, record: ProviderRecord) -> Dict:
        metadata = record.body.get("metadata")
        return metadata if isinstance(metadata, dict) else {}

    def verify_subject_binding(self, record: ProviderRecord, case_id: str, subject_digest: str) -> bool:
        metadata = self._metadata(record)
        if metadata.get(CASE_FIELD) != case_id:
            return False
        claimed = str(metadata.get(SUBJECT_FIELD) or "").lower()
        return bool(claimed) and claimed == subject_digest.lower()

    def verify_action_binding(self, record: ProviderRecord, action_event_id: str) -> bool:
        return self._metadata(record).get(ACTION_FIELD) == action_event_id

    def verify_record_digest(self, record: ProviderRecord, claimed_digest: str) -> bool:
        return bool(claimed_digest) and record.digest.lower() == claimed_digest.lower()

    def verify_replay_protection(self, record: ProviderRecord, seen_record_ids: Sequence[str]) -> bool:
        return record.record_id not in set(seen_record_ids)

    def verify_independence(self, record: ProviderRecord, deployment_keys: Sequence[str]) -> bool:
        signer = str(self._metadata(record).get(SIGNER_FIELD) or "").lower()
        if signer and signer in {key.lower() for key in deployment_keys}:
            return False
        return record.source == "verifier_probe"
