# Conformance profiles

A trust policy declares a `level` plus optional constraints. A **profile** is a
named, citable configuration of those inputs, so a procurement document, an RFP
response or an assessment can name the exact thing it requires rather than
describing it in prose.

Two profiles ship with this verifier. Both are cryptographic only: verification
is offline and never calls a service operated by this project.

## `WOS-E4-TWO-PARTY`

**E4 on the cryptography alone. No third party in the loop.**

Requirements it asserts:

- event signatures verify under the keys the operator has provisioned;
- events are bound to a signed batch manifest;
- the Merkle inclusion proof resolves to the manifest root;
- the RFC 3161 timestamp signature authenticates against the TSA trust roots the
  operator has provisioned;
- the WORM evidence copy is intact against its recorded checksums;
- the operator policy sets `require_retention: false`.

What it deliberately does **not** require: a retention receipt, a transparency
log, a network call at verification time or any third-party service.

The parties to the record hold everything needed to verify it: the signature, the
timestamp and the inclusion proof. Nothing else is asked to vouch for the record.

Reference policy: `tests/public_tsa_certificates/two-party-standard.json`

```bash
witnessos-verifier verify BUNDLE \
  --trust-policy tests/public_tsa_certificates/two-party-standard.json \
  --tsa-url https://freetsa.org/tsr
```

Both bundled fixtures reach E4, exit 0, under this profile.

## `WOS-E4-TWO-PARTY-RETENTION`

**The same profile with a custodian in the loop.**

Identical requirements plus `require_retention: true`, which makes a signed
retention receipt from the custodian named in the policy a requirement. A bundle
that reaches E4 under `WOS-E4-TWO-PARTY` falls to E3 and exit 1 when the receipt is
absent, so the requirement is observable rather than merely asserted.

Reference policy: `tests/public_tsa_certificates/two-party-requiring-custody.json`

```bash
witnessos-verifier verify BUNDLE \
  --trust-policy tests/public_tsa_certificates/two-party-requiring-custody.json \
  --tsa-url https://freetsa.org/tsr
```

## Relationship to the grade ladder

The ladder closes at E4. A profile selects **which E4 conditions an operator
requires**. It does not create a rung, raise a rung or imply one.

`WOS-E4-TWO-PARTY-RETENTION` is therefore not a stronger grade than
`WOS-E4-TWO-PARTY`. Both top out at E4. The difference is a required attribute:
retention is an attribute of a bundle, never a rung on the ladder. An operator
requires it when their own policy says so, not because the ladder has a higher
place to stand.

## Citing a profile

Name the identifier, not the settings. `Verified under WOS-E4-TWO-PARTY` is
checkable by a third party. "Verified with strong assurance" is not.

When a profile is named in a document, state the identifier, the verifier version
used and the trust roots the operator provisioned. Those three facts are what make
the claim reproducible.
