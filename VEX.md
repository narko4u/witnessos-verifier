> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. Historical assurance claims below must be read with [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md).

# VEX — Vulnerability Exploitability eXchange

Status: current as of v0.2.0 (2026-08-18). Reviewed before each release.

This document states the exploitability status of known vulnerabilities in
the software components of this project, per the OSPS VM-04.02 control.
"Not affected" means the vulnerable component is present in the supply chain
but the vulnerable code path cannot be reached or does not affect the
shipped artifact.

## Component inventory

| Component | Type | Version | Runtime? |
|-----------|------|---------|----------|
| `witnessos_verifier` | Shipped package | 0.2.x | Yes |
| Python standard library | Runtime | 3.10 / 3.11 / 3.12 | Yes |
| PyNaCl | Runtime dep | pinned in pyproject | Yes |
| pytest / coverage | Test-only | pinned in CI | No |
| ruff / bandit | Lint/SAST-only | pinned in CI | No |
| GitHub Actions (checkout, setup-python, gh-release) | CI-only | pinned by SHA | No |

## Statements

| Component | Vulnerability | Status | Justification |
|-----------|---------------|--------|---------------|
| `witnessos_verifier` | (any) | Not affected | CLI-only verifier with no network listeners, no server component, no credential storage; the only external input is the evidence bundle directory supplied by the operator |
| PyNaCl | (any) | Under assessment | Assessed at release time against reachable code paths (Ed25519 verification, box seal only) before a release ships |
| Python standard library | (any) | Under assessment | The shipped artifact is stdlib-first; any stdlib CVE is assessed at release time against reachable code paths |
| Test/lint/build/CI components | (any) | Not affected | Not shipped to end users; only ever run in ephemeral CI on trusted inputs |

## Change policy

- This VEX is updated whenever a new component is added, a vulnerability is
  reported, or a release is prepared.
- New releases must not ship while a High or Medium severity finding in a
  reachable component is unresolved (see `SECURITY.md` remediation
  thresholds).
