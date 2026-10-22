"""Provider corroboration adapters.

E3 rests on a party that is not the deployment. This package is the only place the
verifier may decide that such a party exists, and it decides by asking the party
rather than by reading what the record says about it.

Three trust routes are modelled, and only two of them can ever produce E3:

``PUBLIC_KEY_SIGNATURE``
    The provider signs the acknowledgement with a key the operator provisions in the
    verifier's trust policy. The verifier checks the signature over the binding
    fields. Identity comes from the trust file, never from the bundle.

``VERIFIER_STATE_PROBE``
    The provider signs nothing, but the verifier can ask the provider directly. The
    verifier makes that call itself, over TLS, with its own credentials. What it
    compares is the digest of the response it received against the digest the
    acknowledgement claims. A probe recorded in the bundle is refused: the bundle's
    author could have written it.

``SHARED_SECRET``
    An HMAC webhook signature. Useful transport evidence that a request came from
    someone holding the same secret, and never independent verification: the
    deployment holds that secret too, so the verifier would have to become a party
    to the exchange to check it. This route caps at E2 by construction.

Adapters return verifier-derived conclusions only. No method accepts a caller's
claim that corroboration happened, and no adapter reads a boolean out of a payload.
"""
from .base import (
    CorroborationVerdict,
    ProviderCorroborationAdapter,
    ProviderIdentity,
    ProviderRecord,
    ProviderTransport,
    TrustRoute,
    adapter_for,
    register_adapter,
)
from .stripe import StripeStateProbeAdapter

__all__ = [
    "CorroborationVerdict",
    "ProviderCorroborationAdapter",
    "ProviderIdentity",
    "ProviderRecord",
    "ProviderTransport",
    "StripeStateProbeAdapter",
    "TrustRoute",
    "adapter_for",
    "register_adapter",
]
