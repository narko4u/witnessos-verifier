# WitnessOS Verifier

[![OpenSSF Best Practices - Baseline 1](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_1&label=OpenSSF%20Baseline%201&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138) [![OpenSSF Best Practices - Baseline 2](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_2&label=OpenSSF%20Baseline%202&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138) [![OpenSSF Best Practices - Baseline 3](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_3&label=OpenSSF%20Baseline%203&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138)

> **E4 verification implemented with explicit external trust.** Real RFC 3161 signatures are verified against operator-provisioned trust roots. An authenticated retention receipt is recorded and reported as an attribute of the bundle. It is made a requirement only where an operator's trust policy sets `require_retention`. Both bundled fixtures reach E4 under a policy that does not require custody. See [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md) and [E4-IMPLEMENTATION-REPORT.md](E4-IMPLEMENTATION-REPORT.md).

Standalone verifier for WitnessOS evidence. It checks event and manifest signatures in any of Ed25519, ML-DSA-65 or a hybrid suite declaring both, plus canonical event chains, sequence bounds, event membership and binding to the signed batch root. It also verifies engine-native records directly, so a counterparty can check one with the engine absent. Bundled keys prove consistency with those keys; authenticate their identity independently.

**Composite signatures.** Where a manifest declares a hybrid suite such as `ed25519+ml-dsa-65`, the verifier performs both halves over the same bytes and names the declared suite in its verdict, so the result states what was checked rather than passing silently. It refuses a manifest that declares a hybrid suite but carries no countersignature and it refuses one that carries a countersignature while declaring no suite. A hybrid record therefore cannot be downgraded to its classical half after the fact.

**Proven with the engine absent.** On 2026-10-04 the verifier graded a live hybrid record at E4, exit 0, in a virtual environment where `import witnessos` fails, so the run rests on the record and two public keys and not on any Empire Labs component. The same run refused both tamper variants by name. The record and its landing evidence are published with the post-quantum programme.

| Grade | Required evidence |
|---|---|
| E0 | No events loaded (grade-derivation API) |
| E1 | Events loaded |
| E2 | E1 plus valid event/manifest signatures, chain, sequence and signed batch binding |
| E3 | E2 plus a signed event recording provider acknowledgement |
| E4 | E3 plus bound inclusion proof, authenticated timestamp and an intact WORM evidence copy |

The anchor is the cryptography: the signature, the RFC 3161 timestamp and the Merkle inclusion proof, verified directly by the parties to the record. E3 records the signer's claim about a provider response; it does not independently authenticate a provider or query a live service. E4 requires operator-provisioned TSA trust roots and an intact WORM evidence copy of the timestamped snapshot. A signed retention receipt from a custodian you trust is recorded and reported as an attribute of the bundle. It is made a requirement only where your policy sets `require_retention`. A matching local WORM checksum is not immutability evidence.

The CLI returns exit 1 when supplied evidence fails or cannot be verified. A lower grade may describe checks that passed; it does not override an invalid bundle result.

## Installation

```bash
pip install witnessos-verifier
```

Or from source:

```bash
git clone https://github.com/narko4u/witnessos-verifier.git
cd witnessos-verifier
pip install -e ".[dev]"
```

Requires Python 3.12+ and OpenSSL 3 on PATH for timestamp authentication.

## Usage

```bash
# Verify using independently provisioned trust
witnessos-verifier verify ./path/to/evidence-bundle/ \
  --trust-policy /path/to/operator-policy.json --tsa-url https://freetsa.org/tsr

# Verify in Alpha mode - grades capped at E3
witnessos-verifier verify --alpha ./path/to/evidence-bundle/

# Get version
witnessos-verifier --version
```

## Example fixtures

Fixtures are unchanged from the upstream review except `e4-stripe-refund`, whose
events/root/proof/timestamp were regenerated on 2026-09-08 so canonical events
reproduce the signed Merkle root (previously the root binding failed, capping the
lane at E1).

- `e4-gmail-approved-send`: signatures and signed event-root binding pass. Verified against the real FreeTSA service under the bundled `tests/public_tsa_certificates/two-party-standard.json` policy: E4, exit 0.
- `e4-stripe-refund`: canonical events reproduce the signed Merkle root (fixture regenerated 2026-09-08). Verified under the same policy: E4, exit 0.

Both fixtures reach E4 on the cryptography alone, with no custodian in the loop. Under
`tests/public_tsa_certificates/two-party-requiring-custody.json`, which sets `require_retention`,
both fall to E3 and exit 1, because no authenticated retention receipt is present. With no trust
policy the timestamp cannot be authenticated, so both are E3 and exit 1. Do not present the test
custodian as real WORM custody.

## Development

```bash
# Clone
git clone https://github.com/narko4u/witnessos-verifier.git
cd witnessos-verifier

# Install dev dependencies
pip install -e ".[dev]"

# Run tests (all offline)
pytest tests/ -v

# Verify the fixture
witnessos-verifier verify fixtures/e4-gmail-approved-send/
```

## Architecture

```
src/witnessos_verifier/
├── __init__.py          # Package version
├── cli.py               # Click CLI
├── verifier.py          # Main orchestrator
├── events.py            # Event loading + canonical hashing
├── signatures.py        # Ed25519 signature verification
├── key_registry.py      # Public key management
├── case_chain.py        # Case hash chain verification
├── ledger.py            # Global ledger verification
├── merkle.py            # CT Merkle tree proofs
├── manifest.py          # Signed batch manifest verification
├── timestamp.py         # RFC 3161 timestamp verification
├── worm.py              # WORM evidence integrity
├── der.py               # Minimal ASN.1 DER parser (stdlib only)
└── grades.py            # E1-E4 evidence grade derivation
```

## Timestamp and retention trust

CMS signatures, ESS signer binding, certificate paths at genTime, timestamping
purpose/EKU, digest/policy/nonce constraints and the timestamp trust window are
verified. STANDARD does not check revocation. STRICT/revocation-required policies
fail closed until authenticated CRL/OCSP support exists. Signed retention receipts
prove what an independently trusted custodian attested; the offline verifier does
not query live storage. Whether a receipt is required is an operator decision:
`require_retention` in the trust policy, default `false`, so a two-party record
reaches E4 on the cryptography alone. Two named profiles are defined so a
procurement or assessment document can cite the exact configuration rather than
describe it: `WOS-E4-TWO-PARTY` and `WOS-E4-TWO-PARTY-RETENTION`. See
[PROFILES.md](PROFILES.md) and the exact [bundle recipe](E4-BUNDLE-FORMAT.md).

## Dependencies

- **pynacl** - Ed25519 signature verification
- **click** - CLI
- **asn1crypto** - ASN.1/CMS structure parsing
- **cryptography** - X.509 certificate parsing
- **OpenSSL 3 executable** - RFC 3161 signature and certificate-path verification
- Optional S3 adapters require boto3; they are not used for E4 verification

No gateway, no credentials, no network. **Verification happens on your machine.**

### Dependency management

The project follows a deliberate, minimal dependency policy:

1. **Selection** - new dependencies are avoided unless a standard-library
   alternative does not exist. Cryptographic and ASN.1 dependencies support real signature and certificate verification; see `pyproject.toml`.
2. **Obtaining** - dependencies are declared in `pyproject.toml` and pinned
   through the `uv.lock` lockfile, so every build uses a reproducible set of
   package versions.
3. **Tracking** - dependencies are monitored three ways:
   - **SCA**: every push/PR runs [OSV-Scanner](https://google.github.io/osv-scanner/)
     in the `security` workflow to detect known vulnerabilities in the lockfile.
   - **SBOM**: every release ships a CycloneDX SBOM (`sbom.cdx.json`) listing
     the exact dependency set of the released artifact.
   - **Integrity**: every release asset ships with a Sigstore signature and a
     `SHA256SUMS` checksum manifest (see [Verifying releases](#verifying-releases)).

## Verifying releases

### 1. Integrity (checksums)

Each release ships a `SHA256SUMS` file listing the hashes of every release
asset. To verify that a downloaded asset matches the published release:

```sh
sha256sum -c SHA256SUMS
```

This checks the integrity of the wheel, source tarball, and SBOM against the
hashes generated at release time. The `SHA256SUMS` file itself is attached
to the GitHub release (see the [Releases](https://github.com/narko4u/witnessos-verifier/releases) page), so integrity can be checked without trusting the download mirror.

### 2. Authenticity (Sigstore/cosign signatures)

Every release asset is signed **keylessly** with [Sigstore](https://www.sigstore.dev/)
at build time by the `Release` GitHub Actions workflow. Each asset is shipped
with a `.sig` signature and a `.pem` signing certificate. To verify the
signature of an asset:

```sh
# install cosign: https://docs.sigstore.dev/cosign/installation/
TAG=$(gh release view --repo narko4u/witnessos-verifier --json tagName -q .tagName)  # e.g. v0.3.4
V="${TAG#v}"   # 0.3.4
ART="witnessos_verifier-${V}-py3-none-any.whl"

cosign verify-blob \
  --certificate-identity-regexp "^https://github\.com/narko4u/witnessos-verifier/\.github/workflows/release\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature "${ART}.sig" \
  --certificate "${ART}.pem" \
  "${ART}"
```

The `.pem` asset is stored **base64-wrapped**. `cosign` reads it as it comes out of
the release; a tool that wants a plain PEM (for example `openssl x509`) needs it
decoded first:

```sh
base64 -d "${ART}.pem" > cert.pem
```

`--certificate-identity` compares against one exact string; the `v*` used in
earlier revisions of this section was a glob that no certificate ever carried,
so that command could not have succeeded. Use the regexp form above, or pin
the exact identity of the release you are checking.

### 3. Release author identity

Releases are authored by the **Empire Labs Pty Ltd** maintainer team and
built automatically by the `Release` GitHub Actions workflow in the
`narko4u/witnessos-verifier` repository. The Sigstore certificate embedded in
each `.pem` file binds the asset to that workflow *and* to the git ref the run
executed on, so the ref is part of the identity:

- Releases published by pushing a `v*.*.*` tag carry
  `https://github.com/narko4u/witnessos-verifier/.github/workflows/release.yml@refs/tags/<tag>`.
  The workflow refuses to run from any other ref, so a release cannot be signed
  under an identity that does not name a tag.
- `v0.1.0` and `v0.2.0` were published by a manual backfill that executed
  against `main`, so their certificates carry
  `...release.yml@refs/heads/main` rather than a tag ref. Those assets are
  genuine; their identity does not name the tag they belong to.

Either way the issuer is `https://token.actions.githubusercontent.com`, and the
repository and workflow in the identity must be the ones above - if the
certificate identity does not match, the asset was not produced by this
project's release process.

Note the two cosign flags are not interchangeable:
`--certificate-identity-regexp` accepts a pattern, `--certificate-identity` is
an exact string comparison.

### 4. Software Bill of Materials (SBOM)

Each release ships a CycloneDX SBOM (`sbom.cdx.json`) generated from the
built artifacts by the `Release` workflow. The SBOM lists every runtime and
build dependency so consumers can inventory the supply chain of the wheel
and source tarball. Verify it with the same checksum and signature
verification steps above.

### 5. VEX and threat assessment

The repository also publishes a [VEX](VEX.md) document accounting for known
vulnerabilities that do not affect the project, and a
[threat assessment](THREAT-ASSESSMENT.md) covering the attack surface and
mitigations for each release.

---

## Acknowledgements

The verifier stands on these independent projects:

- **[PyNaCl](https://pynacl.readthedocs.io/)** - Ed25519 signature verification,
  binding to [libsodium](https://doc.libsodium.org/).
- **[cryptography](https://cryptography.io/)** - X.509 certificate parsing.
- **[asn1crypto](https://github.com/wbond/asn1crypto)** - ASN.1 and CMS structure parsing.
- **[Click](https://click.palletsprojects.com/)** - command-line interface.
- **[OpenSSL](https://www.openssl.org/)** 3 - RFC 3161 timestamp signature and
  certificate-path verification, invoked as an external executable.
- **[boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)** -
  optional, for the S3 storage adapters only; not used for E4 verification.

Each is an independent project with its own maintainers and release cycle,
credited here as a dependency. None of them has reviewed, endorsed or certified
this verifier.

---

## License

Apache 2.0 - see [LICENSE](LICENSE)

## Related

- [Conformance profiles](PROFILES.md) - the citable named profiles
- [WitnessOS Spec](https://github.com/narko4u/witnessos) - the protocol specification
- [Contact Empire Labs](mailto:contact@empirelabs.com.au)

---

**Built by Empire Labs Pty Ltd.** WitnessOS is a trademark of Empire Labs.


---

<sub>Part of the [WitnessOS launch family](https://github.com/narko4u/witnessos): [eu-ai-act-compliance-grade](https://github.com/narko4u/eu-ai-act-compliance-grade) · [witnessos-verifier](https://github.com/narko4u/witnessos-verifier) · [agent-interaction-specs](https://github.com/narko4u/agent-interaction-specs) · [aci-spec](https://github.com/narko4u/aci-spec) · [aip-spec](https://github.com/narko4u/aip-spec) · [ajson](https://github.com/narko4u/ajson) - [Empire Labs Pty Ltd](https://www.empirelabs.com.au)</sub>