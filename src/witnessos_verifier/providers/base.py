"""The adapter contract.

An adapter answers one question about one acknowledgement: can the verifier
establish, from something the deployment does not control, that the party named in
the acknowledgement actually said what the acknowledgement claims? Every method
below returns a verifier-derived conclusion, and the only ordering guarantee is that
`corroborate` calls them in the documented sequence and stops recording success at
the first failure.
"""
from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence


class TrustRoute(str, enum.Enum):
    """How identity is established for this provider."""

    PUBLIC_KEY_SIGNATURE = "public_key_signature"
    VERIFIER_STATE_PROBE = "verifier_state_probe"
    SHARED_SECRET = "shared_secret"

    @property
    def can_reach_e3(self) -> bool:
        """A shared secret cannot: the deployment holds the same secret."""
        return self is not TrustRoute.SHARED_SECRET


@dataclass(frozen=True)
class ProviderIdentity:
    """Who the verifier concluded it was talking to, and on what basis."""

    provider_id: str
    route: TrustRoute
    account_id: Optional[str] = None
    key_id: Optional[str] = None
    basis: str = ""
    authenticated: bool = False


@dataclass(frozen=True)
class ProviderRecord:
    """A record the verifier obtained, and a digest of the bytes it obtained.

    ``source`` records who produced the object. A record whose source is the bundle
    is the deployment's own material and cannot establish anything by itself, which
    is why ``from_bundle`` exists and why the state-probe route refuses it.
    """

    provider_id: str
    record_id: str
    digest: str
    body: Dict
    source: str = "verifier_probe"
    signature_b64: Optional[str] = None
    signature_key_hex: Optional[str] = None

    @property
    def from_bundle(self) -> bool:
        return self.source == "bundle"


@dataclass
class CorroborationVerdict:
    """The eight facts, each a conclusion the verifier reached itself."""

    provider_authenticated: bool = False
    record_verified: bool = False
    record_signature_or_trust_route_verified: bool = False
    subject_binding_verified: bool = False
    action_binding_verified: bool = False
    record_digest_verified: bool = False
    replay_protection_verified: bool = False
    independence_verified: bool = False
    provider_id: Optional[str] = None
    signer_identity: Optional[str] = None
    record_id: Optional[str] = None
    route: Optional[TrustRoute] = None
    reasons: list[str] = field(default_factory=list)

    @property
    def satisfied(self) -> bool:
        return all(
            (
                self.provider_authenticated,
                self.record_verified,
                self.record_signature_or_trust_route_verified,
                self.subject_binding_verified,
                self.action_binding_verified,
                self.record_digest_verified,
                self.replay_protection_verified,
                self.independence_verified,
                self.route is not None and self.route.can_reach_e3,
            )
        )

    def fail(self, reason: str) -> "CorroborationVerdict":
        self.reasons.append(reason)
        return self


class ProviderTransport(abc.ABC):
    """The only way an adapter is allowed to reach the provider.

    Kept as an interface so the tests drive the adapter against recorded responses
    rather than against the network, and so a caller cannot quietly substitute a
    bundle field for a live call.
    """

    @abc.abstractmethod
    def get_json(self, url: str, headers: Dict[str, str]) -> tuple[int, Dict]:
        """Perform a GET and return (status_code, parsed body)."""


class ProviderCorroborationAdapter(abc.ABC):
    """One adapter per provider. Subclasses implement the checks, never the policy."""

    provider_id: str = ""
    route: TrustRoute = TrustRoute.PUBLIC_KEY_SIGNATURE

    def __init__(self, transport: Optional[ProviderTransport] = None) -> None:
        self.transport = transport

    # ── the eight facts ────────────────────────────────────────────────

    @abc.abstractmethod
    def authenticate_provider(self) -> Optional[ProviderIdentity]:
        """Establish who the verifier is talking to, or None.

        For the signature route this reads the operator trust file. For the state
        probe route this is the provider's own account endpoint, called with the
        verifier's credentials.
        """

    @abc.abstractmethod
    def fetch_or_verify_record(self, record_id: str) -> Optional[ProviderRecord]:
        """Obtain the record from the provider, or None.

        A record carrying ``source="bundle"`` must be refused by implementations of
        this method on the state-probe route.
        """

    @abc.abstractmethod
    def verify_record_signature_or_trust_route(
        self, record: ProviderRecord, identity: ProviderIdentity
    ) -> bool:
        """Check the signature, or the trust route that replaces it."""

    @abc.abstractmethod
    def verify_subject_binding(
        self, record: ProviderRecord, case_id: str, subject_digest: str
    ) -> bool:
        """The provider's record must speak to this case's subject."""

    @abc.abstractmethod
    def verify_action_binding(
        self, record: ProviderRecord, action_event_id: str
    ) -> bool:
        """The provider's record must name this action, not merely this account."""

    @abc.abstractmethod
    def verify_record_digest(self, record: ProviderRecord, claimed_digest: str) -> bool:
        """The digest the acknowledgement claims must be the digest just obtained."""

    @abc.abstractmethod
    def verify_replay_protection(
        self, record: ProviderRecord, seen_record_ids: Sequence[str]
    ) -> bool:
        """A record already used by another case cannot corroborate this one."""

    @abc.abstractmethod
    def verify_independence(
        self, record: ProviderRecord, deployment_keys: Sequence[str]
    ) -> bool:
        """The record must not be signed by, or about, the deployment's own keys."""

    # ── the policy, which is not a subclass's to change ────────────────

    def corroborate(
        self,
        *,
        record_id: str,
        claimed_digest: str,
        case_id: str,
        action_event_id: str,
        subject_digest: str,
        deployment_keys: Sequence[str] = (),
        seen_record_ids: Sequence[str] = (),
    ) -> CorroborationVerdict:
        verdict = CorroborationVerdict(provider_id=self.provider_id, route=self.route)  # type: ignore[call-arg]

        if not self.route.can_reach_e3:
            return verdict.fail(
                f"{self.route.value}: the verifier would have to hold the provider's own "
                "secret, which makes it a party to the exchange rather than an independent check"
            )

        identity = self.authenticate_provider()
        if identity is None or not identity.authenticated:
            return verdict.fail("provider identity was not established")
        verdict.provider_authenticated = True
        verdict.signer_identity = identity.account_id or identity.key_id or identity.provider_id

        record = self.fetch_or_verify_record(record_id)
        if record is None:
            return verdict.fail("provider record could not be obtained")
        verdict.record_id = record.record_id
        verdict.record_verified = True

        if self.route is TrustRoute.VERIFIER_STATE_PROBE and record.from_bundle:
            return verdict.fail(
                "state probe was supplied by the bundle; the verifier must make that call itself"
            )

        if not self.verify_record_signature_or_trust_route(record, identity):
            return verdict.fail("record signature or trust route did not verify")
        verdict.record_signature_or_trust_route_verified = True

        if not self.verify_subject_binding(record, case_id, subject_digest):
            return verdict.fail("provider record does not speak to this case's subject")
        verdict.subject_binding_verified = True

        if not self.verify_action_binding(record, action_event_id):
            return verdict.fail("provider record does not name this action")
        verdict.action_binding_verified = True

        if not self.verify_record_digest(record, claimed_digest):
            return verdict.fail("provider record digest differs from the digest claimed")
        verdict.record_digest_verified = True

        if not self.verify_replay_protection(record, seen_record_ids):
            return verdict.fail("provider record has already corroborated another case")
        verdict.replay_protection_verified = True

        if not self.verify_independence(record, deployment_keys):
            return verdict.fail("provider record is not independent of the deployment's keys")
        verdict.independence_verified = True

        return verdict


_ADAPTERS: Dict[str, type[ProviderCorroborationAdapter]] = {}


def register_adapter(adapter_cls: type[ProviderCorroborationAdapter]) -> type[ProviderCorroborationAdapter]:
    """Register by provider_id so a caller names a provider, not a class."""
    if not adapter_cls.provider_id:
        raise ValueError("adapter must declare provider_id")
    _ADAPTERS[adapter_cls.provider_id] = adapter_cls
    return adapter_cls


def adapter_for(provider_id: str, transport: Optional[ProviderTransport] = None) -> ProviderCorroborationAdapter:
    try:
        return _ADAPTERS[provider_id](transport=transport)
    except KeyError:
        raise KeyError(
            f"no provider adapter for {provider_id!r}; known: {sorted(_ADAPTERS)}"
        ) from None
