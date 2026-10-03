# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""TSA certificate paths and RFC 3161 signatures via OpenSSL 3.

Trust comes exclusively from operator-provisioned roots. Token certificates
are untrusted chain candidates. No network, system-root fallback, or demo bypass.
"""
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .trust_policy import TrustPolicy, TrustLevel

HAS_CRYPTOGRAPHY = True


@dataclass
class CertChainResult:
    valid: bool
    tsa_cert_subject: str | None = None
    tsa_cert_issuer: str | None = None
    chain_length: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, msg):
        self.errors.append(msg)
        self.valid = False


def run_openssl(args):
    result = subprocess.run(['openssl', *args], capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError('OpenSSL verification failed: ' + result.stderr.decode(errors='replace').strip())


def pem_certificates(paths):
    return [cert for p in paths for cert in x509.load_pem_x509_certificates(Path(p).read_bytes())]


class CertChainValidator:
    def __init__(self, policy: TrustPolicy):
        self.policy = policy

    def validate(self, signing_cert_der: bytes, intermediate_certs=None, *, verification_time=None):
        result = CertChainResult(valid=False)
        try:
            if self.policy.level == TrustLevel.DEMO or not self.policy.trusted_roots:
                raise ValueError('TSA signature requires operator-configured STANDARD/STRICT trusted roots')
            if self.policy.requires_revocation_check():
                raise ValueError('Revocation required but authenticated CRL/OCSP validation is unavailable')
            cert = x509.load_der_x509_certificate(signing_cert_der)
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if not eku.critical or [oid.dotted_string for oid in eku.value] != [self.policy.required_eku]:
                raise ValueError('TSA certificate must have exclusive critical timestamping EKU')
            when = verification_time or datetime.now(timezone.utc)
            if when.tzinfo is None:
                raise ValueError('Certificate verification time must include timezone')
            roots = pem_certificates(self.policy.trusted_roots)
            if not roots:
                raise ValueError('Empty trusted root set')
            candidates = [x509.load_der_x509_certificate(c) for c in (intermediate_certs or [])]
            candidates += pem_certificates(self.policy.untrusted_certificates)
            with tempfile.TemporaryDirectory(prefix='witnessos-cert-') as directory:
                d = Path(directory)
                (d/'roots.pem').write_bytes(b''.join(c.public_bytes(serialization.Encoding.PEM) for c in roots))
                (d/'signer.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                args = ['verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                        '-trusted', str(d/'roots.pem'), '-purpose', 'timestampsign',
                        '-auth_level', '2', '-attime', str(int(when.timestamp()))]
                if candidates:
                    (d/'chain.pem').write_bytes(b''.join(c.public_bytes(serialization.Encoding.PEM) for c in candidates))
                    args += ['-untrusted', str(d/'chain.pem')]
                run_openssl([*args, str(d/'signer.pem')])
            result.valid = True
            result.tsa_cert_subject = cert.subject.rfc4514_string()
            result.tsa_cert_issuer = cert.issuer.rfc4514_string()
        except (ValueError, OSError, x509.ExtensionNotFound, subprocess.SubprocessError) as exc:
            result.add_error(str(exc))
        return result


def wrap_timestamp_resp(token_bytes: bytes) -> bytes:
    """Return a granted TimeStampResp carrying the token, for `openssl ts -verify`.

    Producers differ on which shape they hand over. Some return the full TimeStampResp,
    others the bare TimeStampToken. The engine normalises to the bare token at storage so
    its stored blob is trust-path ready, which means a reader has to put the envelope back
    before OpenSSL will look at it. This is the inverse of that normalisation.

    A blob that is already a TimeStampResp is returned untouched, so both shapes verify.
    """
    from asn1crypto import tsp

    try:
        resp = tsp.TimeStampResp.load(token_bytes, strict=True)
        # asn1crypto parses lazily, so load() succeeds on a bare token and the fault
        # only surfaces when the nested structure is touched. Force it, or this try
        # never fires and a bare token is handed to OpenSSL unwrapped.
        resp['status']['status'].native
        return token_bytes
    except (ValueError, TypeError, KeyError):
        return tsp.TimeStampResp({
            'status': {'status': 'granted'},
            'time_stamp_token': token_bytes,
        }).dump()


def verify_timestamp_response(token_bytes, expected_hash, policy, verification_time, certificates):
    """Verify CMS attributes, ESS signer binding, signature, imprint and path.

    Called after the selected signer's independent path validation. Reads the
    same token snapshot that was parsed, avoiding a second read of the input.
    """
    with tempfile.TemporaryDirectory(prefix='witnessos-ts-') as directory:
        d = Path(directory)
        (d/'token.tsr').write_bytes(wrap_timestamp_resp(token_bytes))
        (d/'roots.pem').write_bytes(b''.join(Path(p).read_bytes()+b'\n' for p in policy.trusted_roots))
        (d/'empty').mkdir()
        args = ['ts', '-verify', '-in', str(d/'token.tsr'), '-digest', expected_hash.hex(),
                '-CAfile', str(d/'roots.pem'), '-CApath', str(d/'empty'),
                '-purpose', 'timestampsign',
                '-auth_level', '2', '-attime', str(int(verification_time.timestamp()))]
        if certificates:
            (d/'chain.pem').write_bytes(b''.join(x509.load_der_x509_certificate(c).public_bytes(serialization.Encoding.PEM) for c in certificates))
            args += ['-untrusted', str(d/'chain.pem')]
        run_openssl(args)


def verify_cms_signed_data_signature(*args, **kwargs):
    """Legacy incomplete API: callers must use the complete timestamp path."""
    return False
