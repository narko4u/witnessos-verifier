"""The adapter contract, driven against a recorded provider rather than the network.

Each test removes exactly one fact and requires the verdict to fall, so the eight
checks are each load-bearing rather than decorative.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from witnessos_verifier.providers import (
    CorroborationVerdict,
    ProviderCorroborationAdapter,
    ProviderIdentity,
    ProviderRecord,
    StripeStateProbeAdapter,
    TrustRoute,
    adapter_for,
    base,
)
from witnessos_verifier.providers.base import ProviderTransport

CASE = "case_stripe_1"
ACTION = "evt_action_1"
SUBJECT = "b" * 64


def _body(**overrides) -> dict:
    body = {
        "id": "pi_3Nprovider",
        "object": "payment_intent",
        "livemode": False,
        "account": "acct_verifier_1",
        "amount": 4200,
        "currency": "aud",
        "status": "succeeded",
        "metadata": {
            "witnessos_case_id": CASE,
            "witnessos_action_event_id": ACTION,
            "witnessos_subject_digest": SUBJECT,
        },
    }
    body.update(overrides)
    return body


class FakeTransport(ProviderTransport):
    def __init__(self, account=None, record=None):
        self.account = account or {"id": "acct_verifier_1", "object": "account"}
        self.record = record if record is not None else _body()
        self.calls: list[str] = []

    def get_json(self, url, headers):
        self.calls.append(url)
        if url.endswith("/account"):
            return 200, self.account
        return 200, self.record


def _digest(body) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.fixture
def stripe_env(monkeypatch):
    monkeypatch.setenv("STRIPE_API_KEY", "sk_test_verifier")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "test")


def _corroborate(adapter, **overrides):
    kwargs = dict(
        record_id="pi_3Nprovider",
        claimed_digest=_digest(_body()),
        case_id=CASE,
        action_event_id=ACTION,
        subject_digest=SUBJECT,
        deployment_keys=(),
        seen_record_ids=(),
    )
    kwargs.update(overrides)
    return adapter.corroborate(**kwargs)


def test_satisfied_when_every_fact_holds(stripe_env):
    adapter = StripeStateProbeAdapter(transport=FakeTransport())
    verdict = _corroborate(adapter)
    assert verdict.satisfied, verdict.reasons
    assert verdict.signer_identity == "acct_verifier_1"
    assert verdict.route is TrustRoute.VERIFIER_STATE_PROBE


def test_no_credentials_means_no_identity(monkeypatch):
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "test")
    verdict = _corroborate(StripeStateProbeAdapter(transport=FakeTransport()))
    assert not verdict.satisfied
    assert "identity was not established" in verdict.reasons[0]


def test_unset_expected_mode_refuses_the_route(stripe_env, monkeypatch):
    monkeypatch.delenv("STRIPE_EXPECTED_LIVEMODE", raising=False)
    verdict = _corroborate(StripeStateProbeAdapter(transport=FakeTransport()))
    assert not verdict.satisfied
    assert "trust route did not verify" in verdict.reasons[0]


def test_livemode_mismatch_is_refused(stripe_env):
    adapter = StripeStateProbeAdapter(transport=FakeTransport(record=_body(livemode=True)))
    verdict = _corroborate(adapter, claimed_digest=_digest(_body(livemode=True)))
    assert not verdict.satisfied


def test_case_binding_mismatch_is_refused(stripe_env):
    body = _body(metadata={**_body()["metadata"], "witnessos_case_id": "other_case"})
    adapter = StripeStateProbeAdapter(transport=FakeTransport(record=body))
    verdict = _corroborate(adapter, claimed_digest=_digest(body))
    assert not verdict.satisfied
    assert "subject" in verdict.reasons[0]


def test_action_binding_mismatch_is_refused(stripe_env):
    body = _body(metadata={**_body()["metadata"], "witnessos_action_event_id": "evt_other"})
    adapter = StripeStateProbeAdapter(transport=FakeTransport(record=body))
    verdict = _corroborate(adapter, claimed_digest=_digest(body))
    assert not verdict.satisfied
    assert "this action" in verdict.reasons[0]


def test_digest_of_a_different_response_is_refused(stripe_env):
    adapter = StripeStateProbeAdapter(transport=FakeTransport())
    verdict = _corroborate(adapter, claimed_digest="0" * 64)
    assert not verdict.satisfied
    assert "digest" in verdict.reasons[0]


def test_replayed_record_is_refused(stripe_env):
    adapter = StripeStateProbeAdapter(transport=FakeTransport())
    verdict = _corroborate(adapter, seen_record_ids=("pi_3Nprovider",))
    assert not verdict.satisfied
    assert "another case" in verdict.reasons[0]


def test_deployment_signed_record_is_not_independent(stripe_env):
    body = _body(metadata={**_body()["metadata"], "witnessos_signer_key": "aa" * 32})
    adapter = StripeStateProbeAdapter(transport=FakeTransport(record=body))
    verdict = _corroborate(adapter, claimed_digest=_digest(body), deployment_keys=("aa" * 32,))
    assert not verdict.satisfied
    assert "independent" in verdict.reasons[0]


class _SharedSecretAdapter(ProviderCorroborationAdapter):
    """An HMAC webhook provider: every check returns True and it still cannot reach E3."""

    provider_id = "hmac_example"
    route = TrustRoute.SHARED_SECRET

    def authenticate_provider(self):
        return ProviderIdentity(self.provider_id, self.route, key_id="k1", authenticated=True)

    def fetch_or_verify_record(self, record_id):
        return ProviderRecord(self.provider_id, record_id, "a" * 64, {})

    def verify_record_signature_or_trust_route(self, record, identity):
        return True

    def verify_subject_binding(self, record, case_id, subject_digest):
        return True

    def verify_action_binding(self, record, action_event_id):
        return True

    def verify_record_digest(self, record, claimed_digest):
        return True

    def verify_replay_protection(self, record, seen_record_ids):
        return True

    def verify_independence(self, record, deployment_keys):
        return True


def test_shared_secret_route_never_reaches_e3():
    verdict = _corroborate(_SharedSecretAdapter())
    assert not verdict.satisfied
    assert "party to the exchange" in verdict.reasons[0]


class _BundleProbeAdapter(StripeStateProbeAdapter):
    """A probe whose record came from the bundle, which the contract must refuse."""

    def fetch_or_verify_record(self, record_id):
        return ProviderRecord("stripe", record_id, _digest(_body()), _body(), source="bundle")


def test_probe_supplied_by_the_bundle_is_refused(stripe_env):
    verdict = _corroborate(_BundleProbeAdapter(transport=FakeTransport()))
    assert not verdict.satisfied
    assert "must make that call itself" in verdict.reasons[0]


def test_the_contract_cannot_be_told_that_corroboration_happened(stripe_env):
    adapter = StripeStateProbeAdapter(transport=FakeTransport())
    with pytest.raises(TypeError):
        adapter.corroborate(  # type: ignore[call-arg]
            record_id="pi_3Nprovider",
            claimed_digest=_digest(_body()),
            case_id=CASE,
            action_event_id=ACTION,
            subject_digest=SUBJECT,
            provider_corroborated=True,
        )


def test_registry_resolves_by_provider_id():
    assert isinstance(adapter_for("stripe", transport=FakeTransport()), StripeStateProbeAdapter)
    with pytest.raises(KeyError):
        adapter_for("not_a_provider")


def test_fresh_verdict_is_never_satisfied():
    assert CorroborationVerdict().satisfied is False
    assert base.TrustRoute.SHARED_SECRET.can_reach_e3 is False
