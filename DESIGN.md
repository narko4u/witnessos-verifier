> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. Historical assurance claims below must be read with [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md).

# Design: witnessos-verifier

This document describes the design of `witnessos-verifier`: the actors, the
actions they perform, and the data flow through the verification pipeline.
It accompanies [THREAT-ASSESSMENT.md](THREAT-ASSESSMENT.md) (threat model) and
[TESTING.md](TESTING.md) (test policy).

## Purpose

`witnessos-verifier` is a standalone, offline verifier for WitnessOS evidence
bundles. Given a bundle of security events (for example a Stripe refund
workflow captured as E4 evidence), it cryptographically verifies that the
events are authentic, unmodified, anchored, and timestamped — without
contacting any gateway, credential broker, or network service.

## Actors

| Actor | Description |
| --- | --- |
| **Evidence producer** | An external system that emits security events and assembles them into an evidence bundle (events + signatures + Merkle proof + timestamp). |
| **Verifier operator** | A user who runs the `witnessos-verifier` CLI against a bundle to obtain a verification report. |
| **Signing key holder** | Holds the Ed25519 private key used to sign event batches. The verifier only ever sees the public key, via `key_registry`. |
| **Timestamping Authority (TSA)** | An RFC 3161 TSA that timestamps the Merkle tree root of a batch. The verifier validates the TSA response (signature, imprint, certificate identity, key usage, policy). |
| **Report consumer** | A human or automated system that reads the verification report (e.g. an auditor). |

## Actions

| Action | Performed by | Implemented in |
| --- | --- | --- |
| Load and canonicalise events | Verifier operator (CLI) | `events.py` |
| Verify batch signatures | Verifier operator | `signatures.py` |
| Verify case hash chain | Verifier operator | `case_chain.py` |
| Verify global ledger | Verifier operator | `ledger.py` |
| Verify Merkle tree proofs | Verifier operator | `merkle.py` |
| Verify signed batch manifests | Verifier operator | `manifest.py` |
| Verify RFC 3161 timestamps | Verifier operator | `timestamp.py` |
| Verify WORM evidence integrity | Verifier operator | `worm.py` |
| Manage public keys | Verifier operator | `key_registry.py` |
| Derive evidence grade (E1–E4) | Verifier operator | `grades.py` |
| Parse ASN.1 DER structures | (internal) | `der.py` |
| Orchestrate verification pipeline | Verifier operator | `verifier.py` |
| Invoke the CLI | Verifier operator | `cli.py` |

## Data flow

```
evidence bundle (fixtures/ or user-supplied)
        │
        ▼
cli.py ──► verifier.py (orchestrator)
              │
              ├──► events.py       (canonical hashing of events)
              ├──► signatures.py   (Ed25519 batch signature check)
              ├──► case_chain.py   (hash chain integrity)
              ├──► ledger.py       (global ledger consistency)
              ├──► merkle.py       (CT Merkle proof vs tree root)
              ├──► manifest.py     (signed batch manifest)
              ├──► timestamp.py    (RFC 3161 token validation)
              ├──► worm.py         (write-once-read-many integrity)
              └──► grades.py       (E1–E4 grade derivation)
                      │
                      ▼
              verification report (stdout / exit code)
```

## Design invariants

1. **Offline by construction.** All cryptographic verification is local; no
   network calls are made from the verification code path.
2. **Minimal dependency surface.** The only external dependency is PyNaCl for
   Ed25519 operations; everything else is Python stdlib (see
   [README.md](README.md#dependencies) for the dependency management policy).
3. **Tamper-evident inputs.** Every stage consumes the output of the previous
   stage; a failure at any stage fails the whole verification.
4. **Trust anchor policy is explicit.** TSA trust (roots, policies, key
   usage, revocation) is configurable and documented; the demonstration
   fixture ships a relaxed policy that is clearly labeled as non-production.
