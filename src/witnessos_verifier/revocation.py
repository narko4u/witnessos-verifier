"""Authenticated CRL checking for historical RFC 3161 timestamp verification.

The question this module answers is narrow and historical:

    Was the TSA signing certificate revoked at the token's genTime?

It is deliberately not "is it revoked now". A certificate revoked in 2027 does
not invalidate a timestamp taken in 2026, and a verifier that collapses the two
rejects perfectly good evidence while looking strict.

Four states, not a boolean:

    GOOD_AT_GENTIME                    eligible for E4
    REVOKED_AT_GENTIME                 no E4
    REVOCATION_INFORMATION_UNAVAILABLE no E4 (could not establish status)
    REVOCATION_INFORMATION_INVALID     no E4 (evidence fetched but unusable)

A CRL is trusted only if it parses, its issuer matches an issuer we can verify
against, its signature checks out, its validity window can speak to the relevant
instant, and its serial lookup is deterministic. HTTP 200 proves nothing.

Fetching is bounded: http/https only, no redirects, connection and read
timeouts, a hard response-size cap. No file://, no local paths, no shell.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)

OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31"
ALLOWED_SCHEMES = ("http://", "https://")
MAX_CRL_BYTES = 1024 * 1024
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0


class RevocationState(Enum):
    GOOD_AT_GENTIME = "good_at_gentime"
    REVOKED_AT_GENTIME = "revoked_at_gentime"
    REVOCATION_INFORMATION_UNAVAILABLE = "revocation_information_unavailable"
    REVOCATION_INFORMATION_INVALID = "revocation_information_invalid"


@dataclass
class RevocationResult:
    state: RevocationState
    reason: str = ""
    source: Optional[str] = None
    gen_time: Optional[datetime] = None
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    revocation_time: Optional[datetime] = None
    checked: bool = False
    detail: dict = field(default_factory=dict)

    @property
    def eligible_for_e4(self) -> bool:
        return self.state is RevocationState.GOOD_AT_GENTIME


def distribution_points(cert) -> List[str]:
    """CRL URIs from the certificate itself.

    The authenticated signer certificate is the only authority for where its
    revocation status lives. A URL taken from bundle metadata is attacker
    controlled and is never used as a source.
    """
    from cryptography.x509.oid import ExtensionOID

    uris: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except Exception:
        return uris
    for point in ext.value:
        if point.full_name is None:
            continue
        for name in point.full_name:
            if name.value and str(name.value).lower().startswith(ALLOWED_SCHEMES):
                uris.append(str(name.value))
    return uris


def _fetch(url: str) -> bytes:
    """Bounded fetch. No redirects, no local files, hard size cap."""
    import urllib.request

    if not url.lower().startswith(ALLOWED_SCHEMES):
        raise ValueError(f"refusing non-http(s) revocation source: {url[:40]}")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D401
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=CONNECT_TIMEOUT) as response:
        data = response.read(MAX_CRL_BYTES + 1)
    if len(data) > MAX_CRL_BYTES:
        raise ValueError("revocation response exceeds size limit")
    return data


def _verify_crl_signature(crl, issuer) -> bool:
    from cryptography.exceptions import InvalidSignature

    public_key = issuer.public_key()
    try:
        if crl.is_signature_valid(public_key):
            return True
    except InvalidSignature:
        return False
    except Exception:
        # A malformed CRL is reported by the caller; the CRL parse must not raise
        # out of a verification path that already has an error channel.
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric import padding

        public_key.verify(
            crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm
        )
        return True
    except Exception:
        return False


def check_revocation_at_gentime(
    signer_cert,
    gen_time: datetime,
    issuer_candidates,
    *,
    extra_urls: Optional[List[str]] = None,
    now: Optional[datetime] = None,
    fetcher=None,
) -> RevocationResult:
    """Establish the signer's revocation status as at `gen_time`.

    `issuer_candidates` are certificates we are willing to authenticate a CRL
    against: the token's own chain certificates and the operator's configured
    trust roots. `extra_urls` come from operator policy, never from the bundle.
    """
    from cryptography import x509

    now = now or datetime.now(timezone.utc)
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    result = RevocationResult(
        state=RevocationState.REVOCATION_INFORMATION_UNAVAILABLE,
        gen_time=gen_time,
    )

    urls = distribution_points(signer_cert) + list(extra_urls or [])
    seen = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))]
    if not urls:
        result.reason = "no CRL distribution point on the TSA certificate and none configured"
        return result

    fetch = fetcher or _fetch
    invalid_seen = None
    for url in urls:
        try:
            raw = fetch(url)
        except Exception as exc:
            logger.warning("CRL fetch failed for %s: %s", url, exc)
            continue
        result.checked = True
        result.source = url
        try:
            crl = x509.load_der_x509_crl(raw)
        except Exception:
            try:
                crl = x509.load_pem_x509_crl(raw)
            except Exception as exc:
                invalid_seen = f"CRL could not be parsed ({type(exc).__name__})"
                continue

        issuer = None
        for candidate in issuer_candidates:
            if candidate.subject != crl.issuer:
                continue
            if _verify_crl_signature(crl, candidate):
                issuer = candidate
                break
        if issuer is None:
            same_name = [c for c in issuer_candidates if c.subject == crl.issuer]
            invalid_seen = (
                "CRL signature does not verify against its named issuer"
                if same_name
                else "CRL issuer does not match any authenticated issuer certificate"
            )
            continue

        this_update = crl.last_update_utc
        next_update = crl.next_update_utc
        result.this_update = this_update
        result.next_update = next_update
        tolerance = timedelta(minutes=5)
        if this_update is None:
            invalid_seen = "CRL has no thisUpdate"
            continue
        if this_update > now + tolerance:
            invalid_seen = "CRL thisUpdate is in the future"
            continue
        if next_update is not None and next_update < gen_time:
            invalid_seen = "CRL expired before the timestamp's genTime, so it cannot speak to that instant"
            continue

        revoked_time = None
        for entry in crl:
            if entry.serial_number == signer_cert.serial_number:
                revoked_time = entry.revocation_date_utc
                break
        result.revocation_time = revoked_time
        if revoked_time is not None and revoked_time <= gen_time:
            result.state = RevocationState.REVOKED_AT_GENTIME
            result.reason = (
                f"TSA signer revoked at timestamp time (revoked {revoked_time.isoformat()} "
                f"<= genTime {gen_time.isoformat()})"
            )
            return result
        result.state = RevocationState.GOOD_AT_GENTIME
        result.reason = (
            "signer not revoked at genTime"
            if revoked_time is None
            else (
                f"revocation effective {revoked_time.isoformat()} is after genTime "
                f"{gen_time.isoformat()}, so it has no retroactive effect"
            )
        )
        return result

    if invalid_seen:
        result.state = RevocationState.REVOCATION_INFORMATION_INVALID
        result.reason = invalid_seen
    else:
        result.state = RevocationState.REVOCATION_INFORMATION_UNAVAILABLE
        result.reason = "no reachable or authenticable CRL distribution point"
    return result
