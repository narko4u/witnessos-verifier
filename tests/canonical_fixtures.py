"""Canonical evidence fixtures, minted by the engine and frozen once.

Each package carries a governed-effect chain built the way the engine builds one:
request, policy permit, dispatch, execution, and (where the package is meant to
be corroborated) a provider attestation bound to a retained provider record. The
anchor is a real RFC 3161 token signed by a fixture TSA.

The grade is never stated in the fixture. The verifier derives it from the facts,
which is the point of these packages: they prove the ladder is reachable from
evidence rather than from an expected value.

The packages were produced with
``witnessos-gateway/scripts/gen_verifier_fixtures.py`` and are committed as
static fixtures so these tests never touch a network.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from witnessos_verifier.trust_policy import TrustLevel, TrustPolicy

FIXTURES = Path(__file__).parent.parent / "fixtures"
TSA_URL = "https://tsa.fixture.invalid/tsr"


def package(name: str) -> Path:
    path = FIXTURES / name
    assert path.is_dir(), f"missing fixture {name}"
    return path


def bundle(name: str) -> Path:
    return package(name) / "bundle"


def providers(name: str = "canonical-e3") -> dict:
    return json.loads((package(name) / "providers.json").read_text())


def policy(name: str, *, require_retention: bool = False) -> TrustPolicy:
    """The operator inputs a relying party would hold.

    For canonical-e4 the fixture TSA's CA is trusted, which is what lets the
    anchor authenticate. The other packages publish no CA, so their anchor cannot
    authenticate and cannot lift the grade.
    """
    trusted = []
    untrusted = []
    if (package(name) / "ca.pem").exists():
        trusted = [package(name) / "ca.pem"]
    if (package(name) / "tsa.pem").exists():
        untrusted = [package(name) / "tsa.pem"]
    return TrustPolicy(
        level=TrustLevel.STANDARD,
        allowed_tsa_urls={TSA_URL},
        trusted_roots=trusted,
        untrusted_certificates=untrusted,
        provider_keys=providers(name),
        require_retention=require_retention,
    )


def demanding(name: str) -> TrustPolicy:
    """The same policy with custody demanded, to prove retention is an attribute."""
    return replace(policy(name), require_retention=True)


def legacy_bundle() -> Path:
    """The pre-audit fixture: still in the tree, still graded, still E2."""
    path = FIXTURES / "e4-stripe-refund"
    assert path.is_dir(), "the legacy fixture must stay in the tree"
    return path


LEGACY_CHAIN = (
    "action.requested",
    "policy.evaluated",
    "approval.granted",
    "dispatch.started",
    "provider.acknowledged",
    "provider.confirmed",
    "anchor.completed",
)
