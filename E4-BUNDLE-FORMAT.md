> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. The body below is retained as a record. It includes historical diagnosis from before 2026-10-04, when retention was treated as a grade requirement.

# Authenticated E4 bundles: operator policy and re-anchoring

This release verifies real RFC 3161/CMS signatures and independent retention
attestations. A timestamp alone proves existence at a time, not storage retention.
No supplied fixture has a real storage custodian receipt. Do not substitute a
bundle author's signature or the test custodian for production evidence.

## Operator trust (outside the evidence directory)

Install Python 3.12+, the project dependencies, and OpenSSL 3 on PATH. Verification
is offline: it never downloads roots, certificates or retention policy from a bundle.
The operator independently authenticates the TSA roots and storage custodian keys.

Example operator policy (replace the public paths and the custodian public key):

```json
{
  "level": "standard",
  "allowed_tsa_urls": ["https://freetsa.org/tsr"],
  "trusted_roots": ["freetsa-root.pem"],
  "untrusted_certificates": ["freetsa-tsa.pem"],
  "timestamp_not_before": "2026-01-01T00:00:00Z",
  "timestamp_not_after": "2027-01-01T00:00:00Z",
  "clock_tolerance": 300,
  "retention_authorities": {
    "INDEPENDENT-CUSTODIAN-ID": "REPLACE_WITH_64_HEX_ED25519_PUBLIC_KEY"
  },
  "minimum_retention_seconds": 86400
}
```

Certificate paths resolve relative to the policy file. The policy and trusted
roots must be outside the evidence directory. Token-embedded certificates and
`untrusted_certificates` are only chain candidates, never new trust anchors.
The URL allowlist is an operator selection constraint; certificate trust and CMS
signatures authenticate the token, not a URL written in bundle metadata.

`standard` validates signatures, certificate paths/purpose at token genTime,
exclusive critical timestamping EKU, algorithm acceptance, the message imprint,
and the configured time window. It does not check revocation. `strict`, or
`check_revocation: true`, fails closed because CRL/OCSP validation is not implemented.
`demo` never authenticates E4. Future timestamps beyond `clock_tolerance` fail.
Optional `max_timestamp_age_seconds` rejects old tokens; it is unset by default
so historical evidence is not rejected merely for being old. A configured nonce
requirement needs the original nonce passed via `--expected-nonce`.

```bash
uv sync --extra dev
uv run witnessos-verifier verify /path/to/bundle \
  --trust-policy /path/to/operator-policy.json \
  --tsa-url https://freetsa.org/tsr
```

## Exact bundle inputs

Required paths are `events/*.json`, `keys.json`, `case_manifest.json`,
`batch_manifest.json`, `merkle_proof.json`, exactly one timestamp response under
`timestamp/`, `worm/batch_store.json`, and `worm/retention.json`.

0. A manifest declaring a `signature_suite` is a composite manifest and takes the
   rules in **Composite signature suites** below. A manifest without that field is a
   version 1 manifest and is verified exactly as it always was, byte for byte.
1. Sort events by integer `seq`. Require gapless sequence, unique event IDs, a
   consistent case ID, and the exact ordered event IDs and sequence bounds in the
   signed batch manifest. Verify each event's Ed25519 signature over the canonical
   object containing `event_id`, `event_type`, `case_id`, `seq`, `prev_hash`, `payload`
   **without** the `signed` object. Accept `signer_key_id` or `key_id` schema as
   implemented by `binding.verify_event_signatures`; do not rewrite signed data.
2. Chain hashing and Merkle leaves use canonical event JSON **including** `signed`:
   Python `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, UTF-8,
   default `ensure_ascii=True`, no terminal newline. The next event's `prev_hash`
   is the lowercase hex SHA-256 of those canonical bytes. Use the existing
   canonical schema exactly, not pretty-printed raw JSON or the unsigned object.
3. Leaf = `SHA256(0x00 || canonical_event_bytes)`. Parent =
   `SHA256(0x01 || left_32_bytes || right_32_bytes)`. At every odd-width level,
   duplicate the last node. This is the repository's **legacy duplicate-last
   convention**, not RFC 6962's unbalanced CT tree. Do not silently switch tree
   algorithms: a different producer convention needs a versioned protocol change.
4. Write that root as 64 lowercase hex characters into `batch_manifest.json` and
   sign its `BatchManifest.signed_data` canonical bytes using the production
   signing workflow. `case_manifest.json` must match case ID and event count.
   Keep signatures, keys and fixtures immutable during this verification task.
5. `merkle_proof.json` contains `leaf_index`, `leaf_hash`, `root`, `proof_hashes`
   (sibling hashes bottom-up), and `tree_size`. Bind its leaf to the indexed loaded
   event and its root to the signed manifest. For seven leaves, use three siblings.
6. Timestamp **32 binary root bytes**, not the ASCII hexadecimal string. The
   timestamp message imprint must be `SHA256(bytes.fromhex(manifest.root))`.
   Save the original query nonce independently if nonce matching is required.

For a newly produced bundle (these commands are a recipe, not actions taken on
production bundles or credentials):

```bash
# In the bundle directory; write intermediate binary input outside the bundle.
python - <<'PY'
import hashlib, json
m = json.load(open('batch_manifest.json'))
print(hashlib.sha256(bytes.fromhex(m['root'])).hexdigest())
PY
# Substitute the printed SHA-256 imprint; openssl -digest does not hash it again.
openssl ts -query -sha256 -digest IMPRINT_HEX -cert -out /work/request.tsq
curl --fail -H 'Content-Type: application/timestamp-query' \
  --data-binary @/work/request.tsq https://freetsa.org/tsr \
  -o timestamp/batch_timestamp.tsr
```

FreeTSA documents this query/response process and certificate retrieval at
[FreeTSA](https://www.freetsa.org/index_en.php). OpenSSL's complete response
verification is documented in [openssl-ts](https://docs.openssl.org/3.1/man1/openssl-ts/).
Certificates in `tests/public_tsa_certificates/` are public regression material,
not automatically trusted production roots. Their provenance/fingerprints are
recorded alongside them. The explicitly pinned FreeTSA legacy root has noncritical
Basic Constraints; ordinary OpenSSL path validation accepts it as an explicit
trust anchor. We do not enable the blanket `-x509_strict` flag that rejects that
root. Normal path/purpose/critical-extension checks and the explicit TSA EKU check
still run, with no system-root fallback in the independent chain validation.

## Authenticated retention v1

After the finalized evidence (including the verified timestamp token) is stored,
a genuinely independent storage custodian must inspect its immutable object/version
and issue the following attestation using its own private signing service. The
bundle author must not hold that key. This repository only implements the
**verifier**, not a production custodian/issuer or AWS integration.

Compute `snapshot_inventory(bundle_path)` from `worm.py`. It is:

```json
{"schema":"witnessos-snapshot-v1","files":{"relative/path":{"size":123,"sha256":"..."}}}
```

Include every regular file recursively except files under top-level `worm/`.
Paths are POSIX relative paths; sizes and hashes refer to exact file bytes, not
canonicalized contents. The schema binds names, lengths and content separately.
Symlinks are forbidden. `snapshot_sha256` is SHA-256 of `canonical_json(inventory)`:
JSON with sorted keys, compact separators, ASCII escapes, no NaN/Infinity, UTF-8,
no terminal newline. Do not add/edit README or other files after obtaining custody.

`worm/retention.json` must contain exactly these nonempty string fields:

```json
{
  "schema": "witnessos-retention-v1",
  "authority": "INDEPENDENT-CUSTODIAN-ID",
  "batch_id": "SIGNED_BATCH_ID",
  "case_id": "SIGNED_CASE_ID",
  "merkle_root": "SIGNED_ROOT_HEX",
  "snapshot_sha256": "INVENTORY_DIGEST_HEX",
  "object_uri": "s3://custodian-bucket/object",
  "version_id": "IMMUTABLE_OBJECT_VERSION",
  "retention_mode": "COMPLIANCE",
  "issued_at": "2026-09-08T00:00:00Z",
  "retain_until": "2033-09-08T00:00:00Z",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

The signed bytes are `canonical_json(receipt_without_signature)`. The public key
comes only from `retention_authorities` in operator policy and must differ from
all bundled signing public keys. Changing any receipt field invalidates its
signature. The verifier also checks batch/case/root binding, the inventory digest,
the authenticated external timestamp, issuance time versus the anchor/current
clock, and unexpired retention at least as long as operator policy requires.
Unknown issuers, self-attestation, GOVERNANCE mode, stale receipts and editable
local checksums do not satisfy retention.

Retain legacy `worm/batch_store.json` for local consistency: `stored_hash` is
SHA-256 of the concatenation of sorted evidence file bytes (excluding top-level
worm), and `file_count` is their count; preserve its batch/case metadata. It is
not the authenticated snapshot digest and grants no retention assurance by itself.
The receipt binds the exact timestamped snapshot via its independently signed
inventory digest. Nothing here guarantees that a dishonest trusted custodian
actually retains data: E4's retention assertion is explicitly conditional on that
external authority, just as TSA assurance depends on the selected TSA.

## Unchanged fixture diagnosis

Both tokens are genuine FreeTSA signatures using ECDSA/SHA-512 for CMS and SHA-256
for the timestamp imprint. They omit certificates, so supply the public TSA signer
certificate as `untrusted_certificates` and independently trust the FreeTSA root.

- Gmail: timestamp 2026-06-27 06:38:00Z, serial 0x05D64584. Event signatures, chain,
  batch binding and inclusion proof pass. **Measured 2026-10-04:** this fixture reaches
  E4, exit 0, under a trust policy that does not require custody. Where a policy sets
  `require_retention`, the authenticated retention receipt is the only missing item. If
  a custodian stores and attests this exact finalized snapshot now, the receipt proves
  retention from its own issuance rather than retroactive retention since June, so no
  re-anchor is needed.
- Stripe: timestamp 2026-06-28 05:37:32Z, serial 0x05D8894A, nonce
  0x96AD64152740F7C4. The TSA authenticates the submitted old root, not the loaded
  events. Signed root is
  `8f8fb08f6759c22ec81355f92ae4b2b42137f8eff23ad8028525cef29be48b9b`;
  recomputed root is
  `24805fe897e9efcc6d863b5ecd67dcf0fae6881ed8bbcad04dacd33fd1a7a8a9`.
  Its proof leaf is also wrong for the loaded first event. Rebuild the root/proof
  from the exact canonical signed events, have the authorized producer re-sign
  the manifest, obtain a new timestamp for the new root, finalize local checksums,
  and obtain the independent custodian receipt over the finalized snapshot.
  Do not reuse the old timestamp or alter fixtures to disguise this mismatch.
  **Measured 2026-10-04:** this rebuild was carried out on 2026-09-08 and the
  fixture now reaches E4, exit 0, under a policy that does not require custody, so
  the signed root and proof reproduce from the loaded events.

No production retention receipt was available during this work. The E4 positive
integration test uses the **real Gmail FreeTSA token** and a clearly labelled
**test-only custodian**, with an ephemeral in-memory signing key. That is a working
cryptographic integration test, not proof that the fixture is stored in production
WORM. The production-retention acceptance criterion remains unfulfilled until an
independent custodian issues a real receipt in the format above.

## Composite signature suites

A batch manifest may be signed with more than one scheme at once, so that a record's
durability does not rest on any single scheme surviving. This is a versioned change to
the manifest only. The tree, the timestamp, the retention receipt and the operator
policy are untouched.

### Why this is a revision and not an extension

A different producer convention needs a versioned protocol change, as stated at
step 3. The version 1 manifest carries `signing_key_id` and a bare base64 `signature`
with no algorithm label at all, so there is nothing to parse and no field in which to
state a suite. Adding one is a producer convention change.

### The version marker is one field

The marker is the presence of `signature_suite`.

- **Absent** means a version 1 manifest. Ed25519 over `signature`. Verified exactly as
  before, byte for byte.
- **Present** means a composite manifest. Every rule here applies.

This deliberately does not use a `schema` string. A schema string plus a separate
suite field would give two sources of truth. A producer could declare the new
version while omitting the suite. One field, one meaning.

### Composite manifest fields

A composite manifest is a version 1 manifest plus three fields:

```json
{
  "signature_suite": "ed25519+ml-dsa-65",
  "countersigner_key_id": "THE_COUNTER_KEY_ID",
  "countersignature": "BASE64_COUNTER_SIGNATURE"
}
```

- `signature_suite` is a lowercase, plus-separated list of scheme labels. It must name at least two schemes. A one-scheme suite is a single-scheme record written the
  long way.
- `countersigner_key_id` must resolve in `keys.json` and must differ from
  `signing_key_id`.
- Each half is verified under the algorithm the key itself declares in `keys.json`.

### What the signature covers

`BatchManifest.signed_data` for a version 1 manifest is exactly the nine fields it has
always been and nothing else. For a composite manifest it additionally covers
`signature_suite` and `countersigner_key_id`. It still excludes `signature` and
`countersignature`.

The suite declaration has to be inside the signed bytes. If it sat beside them, the
counter half and the declaration could be removed together and the remaining classical
signature would still verify over content that had never changed, producing a record
that looks like a version 1 manifest and is accepted as one. Covering the declaration
makes that removal detectable.

Because the two fields are added only when present, a version 1 manifest's signed bytes
are unchanged.

### The refusals

Each of these is a failed verification with a named reason. None is a warning. None is a traceback through the command line.

1. `signature_suite` present and `countersignature` absent.
2. `countersignature` present and `signature_suite` absent.
3. `signature_suite` names a scheme this build cannot perform. A suite naming fewer than two schemes is
   refused on the same ground.
4. The suite's label set does not exactly equal the algorithms the two named keys
   declare in `keys.json`.
5. `signature_suite` present and `countersigner_key_id` absent.
6. Either half fails to verify.

Refusal 4 closes the swap, because a signature from a different key carries a different
declared algorithm and the sets stop matching. Refusal 3 is the one that matters most in
practice: a suite this build cannot perform is an unverifiable record, not a weaker one.
Reading it as the half we can perform is the downgrade this format refuses.

### The event dimension already carries this

`binding.verify_event_signatures` reads `signed.get('algorithm', 'Ed25519')`, so an
event can declare a scheme today and needs no change. This revision touches the manifest
only.
