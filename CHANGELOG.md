# Changelog

## 0.3.4 (2026-09-16)

### Fixed

- **`--version` reported the wrong version.** The CLI read `__version__` from the
  package source while the distribution filename came from `pyproject.toml`, and
  the two literals drifted: 0.3.0, 0.3.1, 0.3.2 and 0.3.3 all shipped a build
  whose own `witnessos-verifier --version` printed `0.2.0`. The version is now
  single-sourced from `src/witnessos_verifier/__init__.py` through
  `[tool.hatch.version]`, and the release workflow asserts the runtime version
  against the tag before anything is signed or uploaded

## 0.3.3 (2026-09-16)

First release published to PyPI, via GitHub OIDC trusted publishing.

### Fixed

- **Publish payload**: the artifact handed to the PyPI upload action now carries
  only the wheel and the sdist. It previously included `SHA256SUMS` and every
  `.sig`/`.pem` sibling, and the action rejects any file that is not a
  distribution (`InvalidDistribution: Unknown distribution format:
  'SHA256SUMS'`), which aborted the upload for 0.3.2. A step in the publish job
  now asserts the payload is distributions only, so a stray file fails with a
  named error instead of mid-exchange with PyPI

### Added

- **PyPI publication**: the distributions are uploaded with build attestations
  attached, so the provenance of the published files can be checked on the
  project page

## 0.3.2 (2026-09-16)

Tagged and released on GitHub; not published to PyPI.

### Fixed

- **Release checksums**: `SHA256SUMS` no longer double-lists the signature and
  certificate siblings of the distributions, which made `sha256sum -c` report
  `FAILED` for files it had just verified

### Notes

- The PyPI publish job failed on this tag because the upload payload carried
  non-distribution files. The fix landed in 0.3.3, which supersedes it. The
  version was not re-cut: 0.3.2 artifacts were already signed into the
  transparency log, and publishing a second, different artifact set under the
  same version number is the defect this project exists to detect

## 0.3.1 (2026-09-16)

Release-integrity and publication-path work. Tagged only; not published to PyPI.

### Added

- **Trusted publishing**: release workflow publishes to PyPI over OIDC with no
  stored API token, held closed until the project's pending publisher exists and
  the repository variable `PYPI_PUBLISH_ENABLED` is `true`
- **Version/tag assertion**: the release build fails before signing or upload if
  a distribution's version does not match the pushed tag
- **Provenance metadata**: package metadata carries Homepage, Repository, Issues
  and Changelog URLs; sources are watermarked with SPDX headers and NOTICE
- **Security gates**: SAST (CodeQL) and SCA (OSV-Scanner) checks, workflow lint,
  and SARIF reporting that does not depend on a paid GitHub plan
- **OpenSSF Best Practices** baseline 1-3 badges, VEX, threat assessment,
  release-verification instructions, DCO, and a dependency management policy

### Changed

- **Signing identity**: a release may only originate from a tag ref, so keyless
  signatures name the tag rather than a branch that later moves
- **Evidence handling**: unbound evidence is rejected and unauthenticated E4
  claims fail closed; RFC 3161 timestamps and independent retention receipts are
  authenticated rather than imprint-checked only

### Fixed

- SARIF gate could never fail; the SAST gate now blocks at error level

## 0.3.0 (2026-07-02)

### Added

- **Alpha mode**: evidence grading is capped at E3 in alpha, with a README
  disclaimer stating the cap

### Changed

- Launch family cross-links and Empire Labs branding in the footer

## 0.2.0 (2026-06-28)

### Added

- **Stripe E4 demonstration fixture**: 7-event evidence bundle for a Stripe test-mode refund workflow
- **Generator script**: `scripts/generate_stripe_demo_fixture.py` - reproducible E4 bundle generator
- **README**: Clear statement of what offline verification proves vs. what it does not

### Changed

- **Version bump**: 0.1.0 → 0.2.0

## 0.1.0 (2026-06-27)

Initial public release of the WitnessOS standalone open-source verifier.

### Features

- **CLI**: `witnessos-verifier verify ./bundle/` command
- **Event loading**: Parse canonical JSON events with hash computation
- **Case hash chain**: Verify prev_hash links across events
- **Ledger verification**: Validate monotonic sequence numbers and head consistency
- **Merkle proofs**: CT Merkle tree inclusion and consistency proof verification
- **Manifest verification**: Ed25519 signature verification on signed batch manifests
- **Timestamp verification**: RFC 3161 timestamp token parsing and imprint verification
- **WORM integrity**: Evidence bundle hash comparison against stored records
- **Grade derivation**: E1-E4 evidence grading
- **Offline fixture**: Sanitised E4-grade evidence bundle for testing
- **Zero network requirement**: All verification runs entirely offline

### Dependencies

- Python 3.10+
- PyNaCl >= 1.5.0 (sole external dependency)

### Known limitations

- Certificate chain validation in timestamps is not yet implemented (imprint verification only)
- Only Ed25519 signatures are supported
- No WASM/JavaScript build for browser verification (planned)

---

[Unreleased]: https://github.com/narko4u/witnessos-verifier/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.3.4
[0.3.3]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.3.3
[0.3.2]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.3.2
[0.3.1]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.3.1
[0.3.0]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.3.0
[0.2.0]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.2.0
[0.1.0]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.1.0
