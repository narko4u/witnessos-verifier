> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. Historical assurance claims below must be read with [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md).

# Testing Policy

This document defines the project's policy for automated tests: **when** they
are run, **what** they cover, and **how** they must be extended for changes to
the codebase. It is a normative part of the contribution process (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

## When tests are run

- **Locally** — every contributor MUST run the full suite before opening a
  pull request:
  ```bash
  pip install -e ".[dev]"
  pytest tests/ -v
  ```
- **Continuously (CI)** — the full suite runs automatically on every push to
  `main` and on every pull request via the `CI` workflow
  (`.github/workflows/ci.yml`). CI installs the package into a fresh virtual
  environment and runs `pytest --cov=witnessos_verifier`. A pull request that
  fails CI cannot be merged.
- **Before every release** — the maintainers run the suite on the tagged
  commit, and the `Release` workflow builds the artifacts from that exact
  commit.

## The built-artifact gate

Every external claim this project makes resolves to the artefact a user
installs, never to a working tree. The test suite imports the source tree, so a
packaging fault is invisible to it. The gate closes that gap:

```bash
scripts/verify_release_artifact.sh [--wheel PATH] [--bundle DIR]
```

It builds the wheel, installs it into a throwaway virtualenv that cannot see the
source tree and then asserts:

1. the package resolves inside that clean room and carries no editable-install
   marker;
2. three versions agree: the wheel filename, the wheel metadata and the CLI's own
   `--version` output, and all three agree with `pyproject.toml`;
3. the real CLI grades both shipped fixtures as documented, asserting the grade
   **and** the exit code for a no-custody policy (E4, exit 0), a custody-required
   policy (E3, exit 1) and no policy at all (E3, exit 1).

It runs as the `release-artifact` job in CI and again inside the `Release`
workflow before anything is signed or published. A wheel that has never been
executed is not a release.

**Why it exists.** On 2026-10-04 building the wheel caught a defect no test could
see: `pyproject.toml` declared 0.3.0 and the wheel metadata said 0.3.0, while
`witnessos-verifier --version` reported 0.2.0, because `__init__.py` hardcoded its
own copy of the version. `tests/test_version.py` now guards that specific defect
from the inside, and the gate guards the whole class from the outside.

## Test suite layout

- `tests/` — offline tests for all verification logic: event loading,
  canonical hashing, signature verification, Merkle proofs, manifest checks,
  RFC 3161 timestamp validation, WORM integrity, and grade derivation.
- `fixtures/` — sanitised, self-contained evidence bundles used as test input
  (for example `fixtures/e4-gmail-approved-send/` and
  `fixtures/e4-stripe-refund/`). Fixtures never contain real credentials or
  live-service data.
- Tests are deliberately **offline** — no network access is required.

## Policy: major changes MUST add or update automated tests

Any change that alters behaviour of the software produced by this project is a
**major change** and MUST include tests in the same pull request:

- New or changed verification logic (signature, hashing, chain, ledger,
  manifest, timestamp, WORM, grade derivation) — MUST add tests covering the
  new behaviour, including at least one negative case (a crafted input that
  must be rejected).
- New or changed CLI options or output formats — MUST add or update tests that
  exercise the CLI entry point.
- New or changed parsing of evidence bundle fields — MUST add tests for valid
  input, malformed input, and boundary cases.
- New or changed trust-policy behaviour — MUST add tests for both the allowed
  and the denied policy paths.

Changes that are purely editorial (documentation, comments, formatting) do not
require new tests, but the existing suite MUST still pass.

## Code coverage

CI enforces a coverage report. Pull requests that introduce a significant drop
in coverage (as judged by the maintainers against the CI report) are not
merged until the gap is closed with tests.

## Reviewing the results

CI reports per-test results plus a coverage summary. A passing run means:

1. Every test in `tests/` passed in a clean environment.
2. The CLI entry point loads and reports the version declared in
   `pyproject.toml`.
3. The built-artifact gate passed, so the graded result holds for the wheel a
   user installs and not only for the source tree.
4. Coverage was reported so maintainers can judge whether new code is tested.

If a test fails, fix the code or the test — never weaken or delete a failing
test to make CI pass without a maintainer review.
