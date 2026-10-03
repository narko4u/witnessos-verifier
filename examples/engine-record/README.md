# A hybrid record, verified with the engine absent

This directory holds one real record produced by the WitnessOS engine, together with
everything a third party needs to check it.

| File | What it is |
|---|---|
| `manifest.json` | The batch manifest, signed with **Ed25519 and ML-DSA-65** |
| `keys.json` | The two public keys that verify those signatures |
| `leaves.json` | The per-event leaf hashes the Merkle root is built from |
| `timestamp.tsr` | An **RFC 3161 token from FreeTSA**, stored as the bare token |
| `RECEIPT.txt` | The verifier's output for this record, printed |

## Check it

```
pip install -e .
witnessos-verifier verify-engine examples/engine-record
```

The command reports whether the engine is importable on your machine, so you can see for
yourself that the check is independent. Nothing calls Empire Labs, and no account is needed.

## What it proves, and what it does not

It proves that a counterparty can verify a post-quantum hybrid signature and an external
timestamp offline, from the record and two public keys, with no party of ours in the loop.

It does **not** prove that any particular action happened. The record here is a
demonstration batch from a development store signed with throwaway keys. Real records carry
real keys and real cases, and the same command verifies them.

## A note on the timestamp token

Authorities differ on which shape they return. FreeTSA returns a bare `TimeStampToken`
rather than a `TimeStampResp`, and the engine normalises to the bare token at storage. The
verifier accepts both and reconstructs the envelope for `openssl ts -verify`.

The imprint is SHA-256 of the **32 binary root bytes**, not the ASCII hex string. A reader
that hashes the string will reject a valid token, which is worth knowing before you write
one.
