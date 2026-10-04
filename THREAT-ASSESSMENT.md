> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. Historical assurance claims below must be read with [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md).

# Security Assessment

Status: assessment performed for the v0.2.0 release (2026-08-18). This
document records the most likely and impactful potential security problems
for this software and the mitigations in place. It is reviewed before each
release.

## What this software is

A command-line verifier that replays WitnessOS evidence bundles: it checks
Ed25519 signatures, Merkle-tree proof structure, and RFC 3161 timestamps
against a configured trust policy, fully offline. It has no network
listeners, no server component, and stores no credentials.

## Assets

1. **Verification correctness** — the ability to detect a tampered or
   invalid evidence bundle.
2. **Confidentiality of evidence contents** — evidence bundles may contain
   sensitive operation records.

## Likely and impactful problems

| # | Problem | Likelihood | Impact | Mitigation |
|---|---------|------------|--------|------------|
| 1 | Crafted evidence bundle bypassing signature checks (e.g. wrong public key accepted) | Medium | High (breaks the core promise) | Strict key pinning to the bundle's declared public keys plus configurable trust policy; fixtures cover wrong-key, replayed, and truncated bundles |
| 2 | Hash confusion (non-canonical encoding) | Medium | High (proof malleability) | Canonical serialization in hashing; tests cover field ordering |
| 3 | Maliciously crafted input files (huge, deeply nested, or malformed) | Medium | Low-Medium (DoS of the verifier) | Bounded parsing expectations; CLI is local and user-invoked; no network exposure |
| 4 | Timestamp authority forgery / MITM | Low | High | RFC 3161 responses validated against configured TA trust policy; offline replay of the chain |
| 5 | Dependency supply-chain risk | Low | Low | Minimal runtime dependencies (PyNaCl only); CI installs from pinned source |
| 6 | Secret/credential leakage into evidence bundles | Low | High | Verifier never writes credentials; examples are fictional |

## Threat model scope

- **In scope:** CLI input handling, signature verification, Merkle proof
  checking, RFC 3161 timestamp validation, hash-chain construction.
- **Explicitly out of scope:** the WitnessOS gateway and credential
  brokering (proprietary components, not in this repository), transport
  security of evidence delivery, identity issuance.

## Attack surface analysis

Critical code paths, functions, and interactions, with the threats
considered for each:

- `verify` CLI entry point — input validation and bundle loading.
- Signature verification module — key handling and Ed25519 checks.
- Merkle proof checker — tree structure validation.
- Timestamp validation — RFC 3161 response parsing and trust-policy checks.
