"""PV-RV-01..07 — historical revocation at genTime.

These are security regressions for the question a timestamp verifier must
answer: was the TSA signer revoked at the instant it signed? Every case uses
generated certificates and signed CRLs with a stub fetcher, so the suite never
touches the network and never depends on a third party's uptime.
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from witnessos_verifier.revocation import (
    RevocationState,
    check_revocation_at_gentime,
)

GEN_TIME = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
CRL_URL = "http://crl.test.test/issuer.crl"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn="Test CA"):
    key = _key()
    now = GEN_TIME - timedelta(days=3650)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(GEN_TIME + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _tsa(ca_cert, ca_key, cn="Test TSA"):
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(GEN_TIME - timedelta(days=365))
        .not_valid_after(GEN_TIME + timedelta(days=365))
        .add_extension(
            x509.CRLDistributionPoints(
                [x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                    relative_name=None, reasons=None, crl_issuer=None)]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _crl(issuer_cert, signing_key, *, revoked=(), this_update=None, next_update=None,
         issuer_name=None):
    this_update = this_update or GEN_TIME - timedelta(days=1)
    next_update = next_update or GEN_TIME + timedelta(days=30)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name or issuer_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    for serial, when in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(when)
            .build()
        )
    return builder.sign(signing_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )


def _stub(payload=None, error=None, calls=None):
    def fetch(url):
        if calls is not None:
            calls.append(url)
        if error is not None:
            raise error
        return payload

    return fetch


def _check(tsa_cert, ca_cert, fetcher):
    return check_revocation_at_gentime(
        tsa_cert, GEN_TIME, [ca_cert], fetcher=fetcher, now=GEN_TIME + timedelta(hours=1)
    )


def test_pv_rv_01_valid_crl_signer_not_revoked():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    calls = []
    result = _check(tsa_cert, ca_cert, _stub(_crl(ca_cert, ca_key), calls=calls))
    assert result.state is RevocationState.GOOD_AT_GENTIME
    assert result.eligible_for_e4 and result.checked
    assert calls == [CRL_URL], "the certificate's own distribution point is what gets fetched"


def test_pv_rv_02_crl_unavailable():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    result = _check(tsa_cert, ca_cert, _stub(error=OSError("connection refused")))
    assert result.state is RevocationState.REVOCATION_INFORMATION_UNAVAILABLE
    assert not result.eligible_for_e4


def test_pv_rv_03_revoked_before_gentime():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    crl = _crl(ca_cert, ca_key, revoked=[(tsa_cert.serial_number, GEN_TIME - timedelta(minutes=5))])
    result = _check(tsa_cert, ca_cert, _stub(crl))
    assert result.state is RevocationState.REVOKED_AT_GENTIME
    assert not result.eligible_for_e4
    assert "revoked at timestamp time" in result.reason


def test_pv_rv_04_revoked_after_gentime_is_historical_pass():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    crl = _crl(ca_cert, ca_key, revoked=[(tsa_cert.serial_number, GEN_TIME + timedelta(minutes=5))])
    result = _check(tsa_cert, ca_cert, _stub(crl))
    assert result.state is RevocationState.GOOD_AT_GENTIME
    assert result.eligible_for_e4
    assert result.revocation_time is not None


def test_pv_rv_05_crl_signature_invalid():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    impostor_key = _key()  # right issuer name, wrong key
    crl = _crl(ca_cert, impostor_key)
    result = _check(tsa_cert, ca_cert, _stub(crl))
    assert result.state is RevocationState.REVOCATION_INFORMATION_INVALID
    assert not result.eligible_for_e4


def test_pv_rv_06_crl_issuer_mismatch():
    ca_cert, ca_key = _ca()
    other_ca, other_key = _ca("Somebody Else CA")
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    crl = _crl(other_ca, other_key)
    result = _check(tsa_cert, ca_cert, _stub(crl))
    assert result.state is RevocationState.REVOCATION_INFORMATION_INVALID
    assert "issuer" in result.reason.lower()
    assert not result.eligible_for_e4


def test_pv_rv_07_malformed_crl():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    result = _check(tsa_cert, ca_cert, _stub(b"\x30\x03not-a-crl"))
    assert result.state is RevocationState.REVOCATION_INFORMATION_INVALID
    assert not result.eligible_for_e4


def test_pv_rv_08_expired_before_gentime_cannot_speak_to_the_instant():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    stale = _crl(ca_cert, ca_key,
                 this_update=GEN_TIME - timedelta(days=90),
                 next_update=GEN_TIME - timedelta(days=60))
    result = _check(tsa_cert, ca_cert, _stub(stale))
    assert result.state is RevocationState.REVOCATION_INFORMATION_INVALID
    assert "expired before" in result.reason
    assert not result.eligible_for_e4


def test_pv_rv_09_operator_crl_url_is_additive_not_a_bundle_assertion():
    ca_cert, ca_key = _ca()
    tsa_cert, _ = _tsa(ca_cert, ca_key)
    calls = []
    result = check_revocation_at_gentime(
        tsa_cert, GEN_TIME, [ca_cert],
        extra_urls=["http://operator.test/issuer.crl"],
        fetcher=_stub(_crl(ca_cert, ca_key), calls=calls),
        now=GEN_TIME + timedelta(hours=1),
    )
    assert result.eligible_for_e4
    assert calls[0] == CRL_URL
