# Corroboration: how E3 is established

**Status:** normative for the verifier's E3 appraisal
**Applies to:** E3 Corroborated, and therefore to E4 Anchored, which presupposes it

## 1. The defect this document closes

Until 2026-10-21 the verifier asked one question about E3: does the bundle contain
an event whose type is `provider.confirmed` or `provider.acknowledged`? The bundle
author chooses the event types and holds the signing key, so the answer was always
available to whoever wrote the bundle. A deployment could write an acknowledgement,
sign it with the same key that signed everything else, publish that key in its own
`keys.json`, and be graded E3 Corroborated. Add a real RFC 3161 token and it was
graded E4 Anchored.

That is now refused. E3 is a conclusion the verifier reaches, never a field the
producer fills in.

## 2. What the appraisal checks

E3 requires all five. Each is checked against something the deployment does not
control, or against the bundle's own contents in a way that catches self-agreement.

| Fact | What establishes it |
|---|---|
| provider authentication present | the acknowledgement payload carries a `provider_authentication` block |
| cryptographic integrity | an Ed25519 signature over the binding fields verifies under the stated key |
| identity | that public key is provisioned in the verifier's own trust file, which the deployment cannot write |
| independence | that key is not one of the keys the bundle publishes in `keys.json` |
| provenance | the block names a provider record id that is not the acknowledgement's own event id, and a digest that is not the acknowledgement's own digest |
| binding and replay | the block commits to this case, to an earlier action event in this case, and to the Merkle root of this case's events before the acknowledgement |

A failure in any one of them caps the record at E2. Every failure is reported with
its own reason so a reader can see which fact was missing rather than being told
the grade is lower.

## 3. The block

```json
"provider_authentication": {
  "scheme": "ed25519",
  "public_key_hex": "…64 hex characters…",
  "signature_b64": "…signature over the canonical JSON of the five fields below…",
  "provider_record_id": "pi_3Nprovider",
  "provider_record_digest": "…sha256 of the provider's own record…",
  "action_event_id": "evt_action",
  "replay_root": "sha256:…root over this case's events with seq below this one…"
}
```

The signed body is the canonical JSON of `provider_record_id`,
`provider_record_digest`, `action_event_id`, `replay_root` and
`provider_public_key_hex`. Every binding claim is covered by the provider's
signature rather than sitting beside it.

## 4. What the operator provisions

The verifier reads `WITNESSOS_PROVIDER_KEYS_FILE`, defaulting to
`~/.witnessos/trust/provider_keys.json`:

```json
{"provider_keys": [
  {"scheme": "ed25519", "public_key_hex": "…", "identity": "Stripe", "key_id": "stripe_prod_1"}
]}
```

A flat `{"<public_key_hex>": "Stripe"}` map is also accepted. A missing, empty or
unparsable file is an empty registry, so nothing reaches E3. That is deliberate: a
verifier that cannot read its trust input must not guess who a key belongs to.

This is the one input E3 has that a bundle cannot supply. It is the same shape as
the TSA roots and retention authorities the verifier already requires for E4.

## 5. What still caps at E2

- A provider that authenticates with a shared secret (an HMAC webhook signature)
  rather than a public key. The verifier cannot hold the provider's secret without
  becoming a party to it, so such an acknowledgement is E2 evidence. Reaching E3
  for those providers needs an out-of-band state probe the verifier performs
  itself, which is a verifier capability rather than a bundle field.
- An acknowledgement that does not commit to the prior events, because a replayed
  acknowledgement is otherwise indistinguishable from a fresh one.
- A deployment that signs its own provider responses. This is the defect, and it
  now reads as E2 rather than being rewarded.
