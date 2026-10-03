# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""RFC 3161 timestamp token verification with trust-policy enforcement.

Verifies RFC 3161 Timestamp Response tokens (TimeStampResp)
containing CMS SignedData with TSTInfo.

The verifier:
1. Parses the DER-encoded TimeStampResp
2. Extracts SignedData content and TSTInfo (message imprint, genTime, serial, nonce, policy)
3. Validates message imprint matches the expected hash
4. Enforces TSA provider allowlist from trust policy
5. Validates algorithm acceptance (hash + signature)
6. Checks policy OID against configured trust policy
7. Verifies certificate chain to trusted root CAs (when trust level >= STANDARD)
8. Validates id-kp-timeStamping EKU on TSA certificate
9. Checks certificate expiry
10. Supports dual-anchor verification (primary + secondary TSA)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .trust_policy import TrustPolicy, TrustPolicyResult, TrustLevel, DEFAULT_POLICY


class TimestampError(Exception):
    """Timestamp verification error."""


@dataclass
class TimestampInfo:
    """Extracted TSTInfo contents."""
    version: int
    policy: str
    message_imprint_alg: str  # OID string
    message_imprint: bytes
    serial_number: int
    gen_time: str
    nonce: Optional[int] = None
    accuracy: Optional[dict] = None


@dataclass
class TimestampResult:
    """Result of timestamp token verification."""
    valid: bool
    signature_verified: bool = False
    trust_verified: bool = False
    tst_info: Optional[TimestampInfo] = None
    cert_chain: List[bytes] = field(default_factory=list)
    imprint_matches: bool = False
    errors: List[str] = field(default_factory=list)
    trust_policy_result: Optional[TrustPolicyResult] = None

    @property
    def trust_checks_passed(self) -> bool:
        """Whether trust-policy checks (if run) all passed."""
        if self.trust_policy_result is None:
            return True  # No policy was applied
        return self.trust_policy_result.passed


@dataclass
class DualAnchorResult:
    """Result of dual-anchor timestamp verification."""
    grade: str  # "E4", "E4-degraded", or "E3"
    primary: Optional[TimestampResult] = None
    secondary: Optional[TimestampResult] = None
    errors: List[str] = field(default_factory=list)

    @property
    def is_e4(self) -> bool:
        return self.grade == "E4"

    @property
    def is_degraded(self) -> bool:
        return self.grade == "E4-degraded"


def verify_timestamp(
    token_path: Path,
    expected_hash: bytes,
    policy: Optional[TrustPolicy] = None,
    tsa_url: Optional[str] = None,
    *,
    expected_nonce: Optional[int] = None,
    now=None,
) -> TimestampResult:
    """Authenticate a TimeStampResp against independently configured TSA roots.

    expected_hash is the already-computed message imprint (SHA-256 of the
    32 binary Merkle-root bytes in the bundle protocol). Certificates are
    validated at authenticated genTime, with an explicit acceptance window
    and future-time check. A configured nonce is compared before acceptance.
    """
    from datetime import datetime, timezone, timedelta
    from asn1crypto import cms, tsp, x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization
    from .cert_chain import CertChainValidator, pem_certificates, verify_timestamp_response
    from .der import validate_der_input

    policy = policy or DEFAULT_POLICY
    trust = TrustPolicyResult(passed=True, revocation_status=policy.effective_revocation_status,
                              trust_level=policy.level.value.upper())
    result = TimestampResult(valid=False, trust_policy_result=trust)
    try:
        raw = token_path.read_bytes()
        issues = validate_der_input(raw, strict=True)
        if issues:
            raise ValueError('; '.join(issues))
        # RFC 3161 defines two shapes and authorities differ on which they return.
        # Most wrap the token in a TimeStampResp. FreeTSA returns the bare
        # TimeStampToken, which is a CMS ContentInfo and is self-contained, so it is
        # accepted directly rather than reported as a malformed response.
        try:
            response = tsp.TimeStampResp.load(raw, strict=True)
            if response.dump(force=True) != raw:
                raise ValueError('Non-canonical DER timestamp response')
            if response['status']['status'].native not in ('granted', 'granted_with_mods'):
                raise ValueError('Timestamp response was not granted')
            token = response['time_stamp_token']
        except (ValueError, TypeError):
            token = cms.ContentInfo.load(raw, strict=True)
            if token['content_type'].native != 'signed_data':
                raise ValueError('Not a TimeStampResp and not a CMS SignedData token')
        if token['content_type'].native != 'signed_data':
            raise ValueError('Timestamp token is not CMS SignedData')
        sd = token['content']
        if sd['encap_content_info']['content_type'].native != 'tst_info':
            raise ValueError('CMS content is not TSTInfo')
        info = sd['encap_content_info']['content'].parsed
        mi = info['message_imprint']
        alg = mi['hash_algorithm']['algorithm'].dotted
        gen_time = info['gen_time'].native
        result.tst_info = TimestampInfo(
            version=1, policy=info['policy'].dotted,
            message_imprint_alg=alg, message_imprint=mi['hashed_message'].native,
            serial_number=info['serial_number'].native, gen_time=gen_time.isoformat(),
            nonce=info['nonce'].native)
        if info['version'].native != 'v1':
            raise ValueError('Unsupported TSTInfo version')
        result.imprint_matches = mi['hashed_message'].native == expected_hash
        if not result.imprint_matches:
            raise ValueError('Message imprint mismatch')
        if not policy.is_hash_algorithm_allowed(alg):
            raise ValueError('Timestamp imprint algorithm rejected by policy')
        if not policy.is_policy_allowed(info['policy'].dotted):
            raise ValueError('Timestamp policy OID rejected')
        if policy.require_nonce_echo and expected_nonce is None:
            raise ValueError('Nonce echo required: supply independently retained expected nonce')
        if expected_nonce is not None and info['nonce'].native != expected_nonce:
            raise ValueError('Timestamp nonce mismatch')
        now = now or datetime.now(timezone.utc)
        if gen_time.tzinfo is None or now.tzinfo is None:
            raise ValueError('Timestamp verification requires timezone-aware UTC instants')
        if policy.clock_tolerance < 0:
            raise ValueError('Negative timestamp tolerance')
        if gen_time > now + timedelta(seconds=policy.clock_tolerance):
            raise ValueError('Timestamp is in the future')
        if policy.timestamp_not_before and gen_time < policy.timestamp_not_before:
            raise ValueError('Timestamp precedes trust window')
        if policy.timestamp_not_after and gen_time > policy.timestamp_not_after:
            raise ValueError('Timestamp exceeds trust window')
        if policy.max_timestamp_age_seconds is not None:
            if policy.max_timestamp_age_seconds < 0 or (now-gen_time).total_seconds() > policy.max_timestamp_age_seconds:
                raise ValueError('Timestamp exceeds maximum age')
        if not policy.is_tsa_allowed(tsa_url):
            raise ValueError('TSA URL not in operator allowlist')
        if policy.level == TrustLevel.DEMO or not policy.trusted_roots:
            raise ValueError('TSA signature requires operator-configured STANDARD/STRICT trusted roots')
        if policy.requires_revocation_check():
            raise ValueError('Revocation required but authenticated CRL/OCSP validation is unavailable')
        signers = sd['signer_infos']
        if len(signers) != 1:
            raise ValueError('Timestamp must have exactly one CMS signer')
        signer = signers[0]
        digest_oid = signer['digest_algorithm']['algorithm'].dotted
        if not policy.is_hash_algorithm_allowed(digest_oid):
            raise ValueError('CMS digest algorithm rejected')
        sig_oid = signer['signature_algorithm']['algorithm'].dotted
        # CMS rsaEncryption carries the digest separately in SignerInfo.
        if sig_oid == '1.2.840.113549.1.1.1':
            sig_oid = {'sha256': '1.2.840.113549.1.1.11', 'sha384': '1.2.840.113549.1.1.12',
                       'sha512': '1.2.840.113549.1.1.13'}.get(signer['digest_algorithm']['algorithm'].native, '')
        if not policy.is_signature_algorithm_allowed(sig_oid):
            raise ValueError('CMS signature algorithm rejected')
        certs = [c.chosen for c in sd['certificates'] if c.name == 'certificate']
        certs += [asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))
                  for c in pem_certificates(policy.untrusted_certificates)]
        certs = list({c.dump(): c for c in certs}.values())
        sid = signer['sid']
        if sid.name == 'issuer_and_serial_number':
            matches = [c for c in certs if c.serial_number == sid.chosen['serial_number'].native
                       and c.issuer.dump() == sid.chosen['issuer'].dump()]
        else:
            matches = [c for c in certs if c.key_identifier == sid.chosen.native]
        if len(matches) != 1:
            raise ValueError('TSA signer certificate missing or ambiguous; supply untrusted_certificates')
        selected = matches[0]
        chain = [c.dump() for c in certs if c.dump() != selected.dump()]
        checked = CertChainValidator(policy).validate(selected.dump(), chain, verification_time=gen_time)
        if not checked.valid:
            raise ValueError('; '.join(checked.errors))
        # Full RFC 3161/ESS/CMS validation, not just a bare signature operation.
        verify_timestamp_response(raw, expected_hash, policy, gen_time, [c.dump() for c in certs])
        result.cert_chain = [c.dump() for c in certs]
        result.signature_verified = True
        result.trust_verified = True
        result.valid = True
        trust.add_pass('CMS signature, ESS signer binding and trusted certificate path verified')
        trust.add_pass('Message imprint and timestamp trust window verified')
    except Exception as exc:
        # Every malformed token/backend failure is a structured verification failure.
        result.errors.append(str(exc))
        trust.add_fail(str(exc))
    return result


def verify_dual_anchor(
    primary_path: Path,
    secondary_path: Optional[Path],
    expected_hash: bytes,
    policy: TrustPolicy,
    primary_url: Optional[str] = None,
    secondary_url: Optional[str] = None,
) -> DualAnchorResult:
    """Verify timestamps from primary and secondary TSA providers.

    E4 requires the primary anchor to pass. If secondary is configured
    but fails, the result is E4-degraded (still E4, but with a warning).
    If neither passes, the result is E3 (no external anchoring).

    Args:
        primary_path: Path to the primary TSA's timestamp token
        secondary_path: Path to the secondary TSA's timestamp token (optional)
        expected_hash: The hash that should be timestamped
        policy: TrustPolicy for validation
        primary_url: URL of the primary TSA
        secondary_url: URL of the secondary TSA

    Returns:
        DualAnchorResult with anchor status.
    """
    errors: List[str] = []

    # Verify primary
    primary = verify_timestamp(primary_path, expected_hash, policy, primary_url)

    if secondary_path and secondary_path.exists():
        secondary = verify_timestamp(
            secondary_path, expected_hash, policy, secondary_url
        )
    else:
        secondary = None

    # Determine grade
    if primary.valid:
        if secondary is not None and not secondary.valid:
            # Primary passes, secondary fails — degraded E4
            errors.append(
                "Secondary TSA verification failed — evidence is E4-degraded"
            )
            return DualAnchorResult(
                grade="E4-degraded",
                primary=primary,
                secondary=secondary,
                errors=errors,
            )
        else:
            # Both pass (or no secondary configured)
            return DualAnchorResult(
                grade="E4",
                primary=primary,
                secondary=secondary,
            )
    elif secondary is not None and secondary.valid:
        # Primary failed but secondary passes — still E4
        errors.append(
            "Primary TSA verification failed — relying on secondary anchor"
        )
        return DualAnchorResult(
            grade="E4",  # Still E4, secondary passed
            primary=primary,
            secondary=secondary,
            errors=errors,
        )
    else:
        # Neither passed
        primary_errors = primary.errors if primary else []
        sec_errors = secondary.errors if secondary else []
        all_errors = (
            ["No valid timestamp anchor"]
            + [f"  Primary: {e}" for e in primary_errors]
            + [f"  Secondary: {e}" for e in sec_errors]
        )
        return DualAnchorResult(
            grade="E3",
            primary=primary,
            secondary=secondary,
            errors=all_errors,
        )
