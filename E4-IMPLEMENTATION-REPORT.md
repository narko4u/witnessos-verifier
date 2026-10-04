> **Current verification contract:** Real TSA authentication is supported with explicit operator trust. A signed retention receipt is recorded as an attribute and is not a grade requirement; it is demanded only where a trust policy sets `require_retention`. STRICT revocation remains unavailable. This report is retained as a historical implementation record. It was written before 2026-10-04, when retention was treated as a grade requirement. See [README.md](README.md) for the current contract.

# E4 authentication implementation report

Base: `648fee3e1c73a2a1ba64385d662276ffda4cd24f` (merged PR #11).
Status: resolved and merged (2026-09-08). Scope: this repository only.

## Phase status

1. **Implemented and verified with both real FreeTSA tokens** —
   `src/witnessos_verifier/timestamp.py:80`, `cert_chain.py:48,86`.
   ASN.1 CMS/TSTInfo parsing, correct signer selection from embedded or externally
   supplied untrusted certificates, full OpenSSL RFC 3161 signature/ESS checks,
   independent operator-root path validation, exclusive critical timestamping EKU,
   algorithms, message imprint, nonce and UTC trust-window checks. The old unconditional
   fail is gone. Genuine Gmail and Stripe signatures pass; altered signatures fail.
2. **Verifier implemented; production custodian evidence unavailable** —
   `src/witnessos_verifier/worm.py:117,133`.
   Exact named/length-bound snapshot inventory plus independently signed Ed25519
   custodian receipt. Checks issuer pin, independence from bundle keys, signature,
   snapshot/batch/root binding, verified external timestamp and active COMPLIANCE
   retention. Local checksums never grant retention. This verifies an external
   custodian's attestation, not a live storage inspection or physical immutability.
3. **Diagnosed without fixture modification; exact recipe delivered** —
   `E4-BUNDLE-FORMAT.md`. Both tokens are genuine. Gmail needs a real independent
   custody receipt. Stripe additionally needs its root/proof rebuilt, a newly signed
   manifest and a new timestamp. The precise canonical bytes, leaf/parent hashes,
   duplicate-last tree rule, TSA imprint and receipt signature inputs are documented.

CLI integration: `src/witnessos_verifier/cli.py:37-59`, `verifier.py:94`.
Policy configuration: `trust_policy.py:71-163`.

## Acceptance evidence and remaining blockers

- All original 57 tests remain unchanged and pass. Total: **100 passed**.
- The original seven attacks pass their negative assertions. They also run against
  a working E4 control with real FreeTSA cryptography and still fail closed.
- Both existing FreeTSA tokens authenticate under explicitly configured provider
  certificates. Tokens omit certificates; the untrusted signer PEM is necessary.
- An end-to-end E4 CLI run succeeds with the genuine Gmail FreeTSA token and a
  **TEST-CUSTODIAN-NOT-PRODUCTION receipt**, signed using a newly generated ephemeral
  in-memory test key. No production private key was accessed or stored.
- **The production E4 acceptance criterion is NOT met.** No independently issued
  production retention receipt or custodian integration was available. The test
  custodian is a cryptographic integration test and must not be presented as real
  WORM custody. The real unchanged Gmail bundle correctly returns E3/exit 1 with
  TSA signature/path true and retention false. Stripe (fixture regenerated
  2026-09-08: events now reproduce the signed Merkle root, re-signed manifest and
  re-anchored timestamp) also returns E3/exit 1 — both lanes grade E4 only under
  an operator trust policy naming a trusted retention authority.
- STRICT/revocation-required operation still fails closed: authenticated CRL/OCSP
  validation is not implemented. STANDARD does not claim revocation checks.
- OpenSSL 3 must be installed. Missing backend fails, with no parser-only fallback.
- The optional old S3 adapter is not used as a retention trust source. An actual
  custodian must inspect immutable storage and issue the documented signed receipt.
- Current Merkle convention is retained, not silently migrated to RFC 6962 CT.

No fixtures, existing keys or credentials changed. Added only public FreeTSA
certificates for explicit offline test trust; source endpoints and fingerprints
are documented. The runtime does not auto-trust these test files. No mirror,
merge, deployment or production storage operation was performed.

## Real CLI output

### Genuine unchanged Gmail bundle (exit 1: missing production custody)

Command:
`uv run witnessos-verifier verify fixtures/e4-gmail-approved-send --trust-policy .git/e4-evidence/operator-policy.json --tsa-url https://freetsa.org/tsr`

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-gmail-approved-send
Grade:  E3
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  TSA signature: True
  TSA trusted path: True
  Trust:   STANDARD → not_required
  WORM:    FAIL
  Retention authenticated: False

Errors:
  ✗ Authenticated retention missing: supply worm/retention.json signed by an independently trusted storage custodian

Warnings (2):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.
  ⚠ Local WORM checksums do not prove remote retention or immutability.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
  ✓ E2: Events bound to signed batch
  ✓ E3: Provider acknowledged
  ✓ E4: Merkle inclusion proof valid
  ✓ E4: RFC 3161 timestamp valid
Requirements not met:
  ✗ E4: Authenticated WORM retention evidence invalid or missing
```

### Real FreeTSA token + TEST custodian (exit 0; NOT production custody)

Command: `uv run witnessos-verifier verify .git/e4-evidence/controlled-gmail --trust-policy .git/e4-evidence/test-custodian-policy.json --tsa-url https://freetsa.org/tsr`

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/.git/e4-evidence/controlled-gmail
Grade:  E4
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  TSA signature: True
  TSA trusted path: True
  Trust:   STANDARD → not_required
  WORM:    PASS
  Retention authenticated: True

Warnings (1):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
  ✓ E2: Events bound to signed batch
  ✓ E3: Provider acknowledged
  ✓ E4: Merkle inclusion proof valid
  ✓ E4: RFC 3161 timestamp valid
  ✓ E4: WORM evidence copy valid
```

### Altered token, same TEST custody policy (exit 1)

Command: `uv run witnessos-verifier verify .git/e4-evidence/forged-gmail --trust-policy .git/e4-evidence/test-custodian-policy.json --tsa-url https://freetsa.org/tsr`

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/.git/e4-evidence/forged-gmail
Grade:  E3
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     FAIL
  TSA signature: False
  TSA trusted path: False
  Trust:   STANDARD → not_required
  WORM:    FAIL
  Retention authenticated: False

Errors:
  ✗ OpenSSL verification failed: Using configuration from /usr/lib/ssl/openssl.cnf
Warning: certificate from '/tmp/witnessos-ts-k4h3g282/chain.pem' with subject '/O=Free TSA/OU=TSA/description=This certificate digitally signs documents and time stamp requests made using the freetsa.org online services/CN=www.freetsa.org/emailAddress=busilezas@mailbox.org/L=Wuerzburg/C=DE/ST=Bayern' is not a CA cert
40D71124077F0000:error:10800069:PKCS7 routines:PKCS7_signatureVerify:signature failure:../crypto/pkcs7/pk7_doit.c:1137:
40D71124077F0000:error:1780006D:time stamp routines:TS_RESP_verify_signature:signature failure:../crypto/ts/ts_rsp_verify.c:148:
  ✗ Authenticated retention: Retention snapshot digest mismatch

Warnings (2):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.
  ⚠ Local WORM checksums do not prove remote retention or immutability.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
  ✓ E2: Events bound to signed batch
  ✓ E3: Provider acknowledged
  ✓ E4: Merkle inclusion proof valid
Requirements not met:
  ✗ E4: RFC 3161 timestamp invalid or missing
  ✗ E4: Authenticated WORM retention evidence invalid or missing
```

### Unchanged Stripe bundle (exit 1)

Command: `uv run witnessos-verifier verify fixtures/e4-stripe-refund --trust-policy .git/e4-evidence/operator-policy.json --tsa-url https://freetsa.org/tsr`

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-stripe-refund
Grade:  E1
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  TSA signature: True
  TSA trusted path: True
  Trust:   STANDARD → not_required
  WORM:    FAIL
  Retention authenticated: False

Errors:
  ✗ Loaded events do not match signed Merkle root
  ✗ Merkle proof: proof is not bound to event and signed root
  ✗ Authenticated retention missing: supply worm/retention.json signed by an independently trusted storage custodian

Warnings (2):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.
  ⚠ Local WORM checksums do not prove remote retention or immutability.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
Requirements not met:
  ✗ E2: Events bound to signed batch
```

### Full suite (exit 0)

Command: `uv run pytest`

```text
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.1, pluggy-1.6.0 -- /workspace/scratch/e23923bfde48/witnessos-verifier/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /workspace/scratch/e23923bfde48/witnessos-verifier
configfile: pyproject.toml
testpaths: tests
plugins: cov-7.1.0
collecting ... collected 100 items

tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_payload] PASSED [  1%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_signature] PASSED [  2%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[delete_proof] PASSED [  3%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[fake_proof] PASSED [  4%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[timestamp_signature] PASSED [  5%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[truncate_events] PASSED [  6%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[malformed_manifest] PASSED [  7%]
tests/test_adversarial_bundle.py::test_real_event_signatures_both_vocabularies[e4-gmail-approved-send] PASSED [  8%]
tests/test_adversarial_bundle.py::test_real_event_signatures_both_vocabularies[e4-stripe-refund] PASSED [  9%]
tests/test_adversarial_bundle.py::test_signature_attack_is_detected_independently PASSED [ 10%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider.acknowledged] PASSED [ 11%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider.confirmed] PASSED [ 12%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider_acknowledged] PASSED [ 13%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider_confirmed] PASSED [ 14%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[events_loaded-E0] PASSED [ 15%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[event_signatures_valid-E1] PASSED [ 16%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[batch_binding_valid-E1] PASSED [ 17%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[has_provider_ack-E2] PASSED [ 18%]
tests/test_adversarial_bundle.py::test_parsing_and_checksums_do_not_make_e4 PASSED [ 19%]
tests/test_authenticated_e4.py::test_real_freetsa_signatures[e4-gmail-approved-send] PASSED [ 20%]
tests/test_authenticated_e4.py::test_real_freetsa_signatures[e4-stripe-refund] PASSED [ 21%]
tests/test_authenticated_e4.py::test_bad_token_rejected[signature] PASSED [ 22%]
tests/test_authenticated_e4.py::test_bad_token_rejected[imprint] PASSED  [ 23%]
tests/test_authenticated_e4.py::test_bad_token_rejected[attributes] PASSED [ 24%]
tests/test_authenticated_e4.py::test_bad_token_rejected[trailing] PASSED [ 25%]
tests/test_authenticated_e4.py::test_bad_token_rejected[truncated] PASSED [ 26%]
tests/test_authenticated_e4.py::test_bad_token_rejected[empty_signers] PASSED [ 27%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[no_roots] PASSED [ 28%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[wrong_root] PASSED [ 29%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[missing_signer] PASSED [ 30%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[demo] PASSED [ 31%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[strict] PASSED [ 32%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[window_before] PASSED [ 33%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[window_after] PASSED [ 34%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[age] PASSED [ 35%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[nonce] PASSED [ 36%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[signature_algorithm] PASSED [ 37%]
tests/test_authenticated_e4.py::test_trust_policy_rejections[tsa_url] PASSED [ 38%]
tests/test_authenticated_e4.py::test_future_timestamp_rejected PASSED    [ 39%]
tests/test_authenticated_e4.py::test_actual_nonce PASSED                 [ 40%]
tests/test_authenticated_e4.py::test_real_crypto_e4_with_test_custodian PASSED [ 41%]
tests/test_authenticated_e4.py::test_retention_attack[signature] PASSED  [ 42%]
tests/test_authenticated_e4.py::test_retention_attack[authority] PASSED  [ 43%]
tests/test_authenticated_e4.py::test_retention_attack[digest] PASSED     [ 44%]
tests/test_authenticated_e4.py::test_retention_attack[expired] PASSED    [ 45%]
tests/test_authenticated_e4.py::test_retention_attack[wrong_batch] PASSED [ 46%]
tests/test_authenticated_e4.py::test_retention_attack[mode] PASSED       [ 47%]
tests/test_authenticated_e4.py::test_retention_attack[missing] PASSED    [ 48%]
tests/test_authenticated_e4.py::test_retention_attack[rename] PASSED     [ 49%]
tests/test_authenticated_e4.py::test_retention_attack[unknown_authority] PASSED [ 50%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[last_payload] PASSED [ 51%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[last_signature] PASSED [ 52%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[delete_proof] PASSED [ 53%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[fake_proof] PASSED [ 54%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[timestamp_signature] PASSED [ 55%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[truncate_events] PASSED [ 56%]
tests/test_authenticated_e4.py::test_original_seven_with_real_trust[malformed_manifest] PASSED [ 57%]
tests/test_authenticated_e4.py::test_fixtures_have_real_tsa_but_no_retention PASSED [ 58%]
tests/test_authenticated_e4.py::test_embedded_tsa_certificate PASSED     [ 59%]
tests/test_authenticated_e4.py::test_missing_crypto_backend_is_failure PASSED [ 60%]
tests/test_authenticated_e4.py::test_retention_key_must_not_be_bundle_key PASSED [ 61%]
tests/test_authenticated_e4.py::test_e4_json_cli_and_alpha PASSED        [ 62%]
tests/test_e2e.py::TestE2EVerification::test_fixture_reports_unverified_anchor PASSED [ 63%]
tests/test_e2e.py::TestE2EVerification::test_all_requirements_in_result PASSED [ 64%]
tests/test_e2e.py::TestE2EVerification::test_external_requirements_explicitly_missing PASSED [ 65%]
tests/test_e2e.py::TestCLIVerify::test_cli_verify_output PASSED          [ 66%]
tests/test_e2e.py::TestEmptyBundle::test_empty_bundle_graceful PASSED    [ 67%]
tests/test_events.py::TestEventLoading::test_loads_all_seven_events PASSED [ 68%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_ids PASSED [ 69%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_seqs PASSED [ 70%]
tests/test_events.py::TestEventLoading::test_events_have_valid_prev_hash_chain PASSED [ 71%]
tests/test_events.py::TestEventLoading::test_canonical_bytes_are_valid_json PASSED [ 72%]
tests/test_events.py::TestEventLoading::test_all_events_signed PASSED    [ 73%]
tests/test_events.py::TestBogusInput::test_empty_dir PASSED              [ 74%]
tests/test_events.py::TestBogusInput::test_invalid_json PASSED           [ 75%]
tests/test_events.py::TestBogusInput::test_missing_fields PASSED         [ 76%]
tests/test_fuzz.py::TestDERInputValidation::test_empty_input PASSED      [ 77%]
tests/test_fuzz.py::TestDERInputValidation::test_garbage_input PASSED    [ 78%]
tests/test_fuzz.py::TestDERInputValidation::test_truncated_sequence PASSED [ 79%]
tests/test_fuzz.py::TestDERInputValidation::test_strict_mode_trailing_garbage PASSED [ 80%]
tests/test_fuzz.py::TestDERInputValidation::test_non_minimal_length_encoding_rejected PASSED [ 81%]
tests/test_fuzz.py::TestDERInputValidation::test_oversized_input PASSED  [ 82%]
tests/test_fuzz.py::TestTSTInfoValidation::test_missing_fields_reported PASSED [ 83%]
tests/test_fuzz.py::TestTSTInfoValidation::test_tst_info_parse_error_message PASSED [ 84%]
tests/test_fuzz.py::TestOIDValidation::test_rejects_unknown_oid PASSED   [ 85%]
tests/test_fuzz.py::TestOIDValidation::test_accepts_known_oid PASSED     [ 86%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all PASSED [ 87%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_standard_policy_blocks_unlisted_tsa PASSED [ 88%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all_hash_algorithms PASSED [ 89%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_no_cert_chain_required PASSED [ 90%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_acknowledged PASSED [ 91%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_confirmed PASSED [ 92%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_no_ack_tsa_present_caps_below_e4 PASSED [ 93%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_full_e4_requires_ack PASSED [ 94%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_alpha_caps_e4_to_e3_only_with_ack PASSED [ 95%]
tests/test_signatures.py::TestDetachedSignature::test_valid_signature PASSED [ 96%]
tests/test_signatures.py::TestDetachedSignature::test_bad_signature PASSED [ 97%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_message PASSED [ 98%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_key PASSED   [ 99%]
tests/test_signatures.py::TestEventSignaturesViaVerifier::test_all_events_pass_verification PASSED [100%]

============================= 100 passed in 0.98s ==============================
```
