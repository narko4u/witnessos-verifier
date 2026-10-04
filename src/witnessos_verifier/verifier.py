# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WitnessOS Verifier — Main orchestrator.

Verifies a complete WitnessOS evidence bundle end-to-end.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .binding import verify_event_signatures, verify_batch_binding
from .case_chain import verify_case_chain, ChainResult
from .events import load_events, Event, EventError
from .grades import derive_grade, GradeResult
from .key_registry import KeyRegistry, KeyRegistryError
from .ledger import verify_ledger_sequence, LedgerResult
from .manifest import BatchManifest, verify_manifest, ManifestResult
from .timestamp import verify_timestamp, TimestampResult
from .worm import verify_worm_bundle, WormResult


logger = logging.getLogger(__name__)

PROVIDER_ACK_TYPES = frozenset({"provider.acknowledged", "provider.confirmed",
                                "provider_acknowledged", "provider_confirmed"})


class VerifyError(Exception):
    """Top-level verification error."""


@dataclass
class VerifyResult:
    """Complete verification result."""
    bundle_path: Path
    valid: bool
    grade: Optional[GradeResult] = None
    events: List[Event] = field(default_factory=list)
    chain_result: Optional[ChainResult] = None
    ledger_result: Optional[LedgerResult] = None
    manifest_result: Optional[ManifestResult] = None
    timestamp_result: Optional[TimestampResult] = None
    worm_result: Optional[WormResult] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def evidence_grade(self) -> str:
        if self.grade:
            return self.grade.grade
        return "NONE"

    @property
    def manifest_suite(self) -> str:
        """The suite the batch manifest declares, empty for a single-scheme record.

        The composite path is checked either way, but a reader who is not told
        cannot distinguish a post-quantum hybrid record from a classical one, and
        that distinction is the entire reason the suite dimension exists. A verdict
        on a hybrid record has to say that it is one.
        """
        if self.manifest_result is None:
            return ""
        return self.manifest_result.signature_suite or ""

    @property
    def composite(self) -> bool:
        """True when the record declares more than one signing scheme."""
        return bool(self.manifest_suite)

    def summary(self) -> str:
        lines = []
        lines.append(f"Bundle: {self.bundle_path}")
        lines.append(f"Grade:  {self.evidence_grade}")
        lines.append(f"Events: {len(self.events)}")

        if self.chain_result:
            status = "PASS" if self.chain_result.valid else "FAIL"
            lines.append(f"  Chain:   {status} ({self.chain_result.verified_links}/{self.chain_result.total_events} links)")

        if self.ledger_result:
            status = "PASS" if self.ledger_result.sequence_monotonic else "FAIL"
            lines.append(f"  Ledger:  {status}")

        if self.manifest_result:
            status = "PASS" if self.manifest_result.valid else "FAIL"
            lines.append(f"  Manifest: {status}")
            if self.manifest_suite:
                counter = "verified" if self.manifest_result.countersignature_valid else "FAILED"
                lines.append(f"  Suite:    {self.manifest_suite} (composite, counter half {counter})")

        if self.timestamp_result:
            status = "PASS" if self.timestamp_result.valid else "FAIL"
            lines.append(f"  TSA:     {status}")
            lines.append(f"  TSA signature: {self.timestamp_result.signature_verified}")
            lines.append(f"  TSA trusted path: {self.timestamp_result.trust_verified}")
            if self.timestamp_result.trust_policy_result:
                tr = self.timestamp_result.trust_policy_result
                lines.append(f"  Trust:   {tr.trust_level} → {tr.revocation_status.value}")

        if self.worm_result:
            status = "PASS" if self.worm_result.valid else "FAIL"
            lines.append(f"  WORM:    {status}")
            lines.append(f"  Retention authenticated: {self.worm_result.retention_verified}")

        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  ✗ {e}")

        return "\n".join(lines)


def verify(bundle_path: Path, alpha_mode: bool = False, *, trust_policy=None, tsa_url=None, expected_nonce=None) -> VerifyResult:
    """Verify a WitnessOS evidence bundle.

    The bundle must contain:
    - events/           Directory of event JSON files
    - keys.json         Public key registry
    - case_manifest.json  Case metadata
    - batch_manifest.json  Batch manifest with signature
    - timestamp/         RFC 3161 timestamp token(s)
    - worm/              WORM evidence bundle

    Returns a VerifyResult with grade and all sub-results.
    """
    errors = []
    warnings = []
    bundle_path = bundle_path.resolve()

    if not bundle_path.exists():
        raise VerifyError(f"Bundle directory not found: {bundle_path}")
    if not bundle_path.is_dir():
        raise VerifyError(f"Not a directory: {bundle_path}")

    if any(p.is_symlink() for p in bundle_path.rglob("*")):
        return VerifyResult(bundle_path=bundle_path, valid=False, errors=["Symlinks are not allowed in evidence bundles"])

    if trust_policy:
        for root in trust_policy.trusted_roots:
            if Path(root).resolve().is_relative_to(bundle_path):
                raise VerifyError('Trusted TSA roots must be provisioned outside the evidence bundle')

    # 1. Load events
    try:
        events = load_events(bundle_path)
    except (EventError, ValueError, TypeError, OSError) as e:
        return VerifyResult(
            bundle_path=bundle_path,
            valid=False,
            errors=[str(e)],
        )
    if not events:
        return VerifyResult(
            bundle_path=bundle_path,
            valid=False,
            errors=["No events found in bundle"],
        )
    events_loaded = True

    # 2. Load key registry
    key_registry = None
    keys_path = bundle_path / "keys.json"
    if keys_path.exists():
        try:
            key_registry = KeyRegistry.from_file(keys_path)
        except (KeyRegistryError, ValueError, TypeError, KeyError, OSError) as e:
            errors.append(f"Key registry: {e}")
    else:
        errors.append("No keys.json found — signatures cannot be verified")

    signature_errors = verify_event_signatures(events, key_registry)
    errors.extend(signature_errors)

    # 3. Verify case hash chain
    chain_result = verify_case_chain(events)

    # 4. Verify ledger sequence
    ledger_result = verify_ledger_sequence(events)

    # 5. Verify manifest
    manifest_result = None
    binding_errors = []
    manifest_path = bundle_path / "batch_manifest.json"
    if manifest_path.exists():
        try:
            manifest = BatchManifest.from_file(manifest_path)
            if key_registry:
                manifest_result = verify_manifest(manifest, key_registry)
                binding_errors = verify_batch_binding(events, manifest, bundle_path)
                errors.extend(binding_errors)
            else:
                errors.append("Cannot verify manifest: no key registry")
        except Exception as e:
            errors.append(f"Manifest verification failed: {e}")
    else:
        errors.append("No batch_manifest.json found")

    # 6. Check for provider acknowledgement
    # Accept BOTH naming conventions: the current engine vocabulary is
    # dot-separated (provider.acknowledged / provider.confirmed) while older
    # bundles used underscores (provider_acknowledged / provider_confirmed).
    has_provider_ack = any(
        e.event_type in PROVIDER_ACK_TYPES
        for e in events
    )

    # 7. Verify timestamp token
    timestamp_result = None
    ts_dir = bundle_path / "timestamp"
    if ts_dir.exists():
        ts_files = sorted(ts_dir.glob("*.tsr")) + sorted(ts_dir.glob("*.der"))
        if len(ts_files) > 1:
            errors.append("Ambiguous timestamp bundle: provide exactly one batch timestamp")
            ts_files = []
        if ts_files:
            # Use batch manifest root hash as expected imprint
            expected_hash = None
            if manifest_path.exists():
                try:
                    with open(manifest_path) as f:
                        mdata = json.load(f)
                        root = mdata.get("root", "")
                        if root:
                            # TSA timestamps SHA-256(root), not root directly
                            root_bytes = bytes.fromhex(root)
                            expected_hash = hashlib.sha256(root_bytes).digest()
                except Exception as e:
                    logger.warning(
                        f"Could not derive expected timestamp imprint from manifest: {e}"
                    )

            if expected_hash:
                try:
                    timestamp_result = verify_timestamp(ts_files[0], expected_hash, trust_policy, tsa_url, expected_nonce=expected_nonce)
                except Exception as e:
                    errors.append(f"Timestamp verification error: {e}")
            else:
                warnings.append("Cannot verify timestamp: no expected hash from manifest")
        else:
            warnings.append("Timestamp directory exists but no .tsr/.der files found")

    # 8. Verify WORM bundle
    worm_result = None
    worm_dir = bundle_path / "worm"
    if worm_dir.exists():
        try:
            worm_result = verify_worm_bundle(worm_dir, bundle_path, trust_policy, timestamp_result)
        except Exception as e:
            errors.append(f"WORM verification error: {e}")

    warnings.append("Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.")
    if not worm_result or not worm_result.retention_verified:
        warnings.append("Local WORM checksums do not prove remote retention or immutability.")

    # 9. Derive grade
    grade = derive_grade(
        events_loaded=events_loaded,
        chain_result=chain_result,
        ledger_result=ledger_result,
        manifest_result=manifest_result,
        has_provider_ack=has_provider_ack,
        timestamp_result=timestamp_result,
        worm_result=worm_result,
        alpha_mode=alpha_mode,
        event_signatures_valid=not signature_errors,
        batch_binding_valid=manifest_result is not None and not any(not e.startswith("Merkle proof:") for e in binding_errors),
        merkle_proof_valid=manifest_result is not None and not any(e.startswith("Merkle proof:") for e in binding_errors),
        require_retention=bool(getattr(trust_policy, "require_retention", False)),
    )

    # Collect all errors
    if chain_result and chain_result.errors:
        errors.extend(chain_result.errors)
    if ledger_result and ledger_result.errors:
        errors.extend(ledger_result.errors)
    if manifest_result and manifest_result.errors:
        errors.extend(manifest_result.errors)
    if timestamp_result and timestamp_result.errors:
        errors.extend(timestamp_result.errors)
    if worm_result and worm_result.errors:
        errors.extend(worm_result.errors)
    if worm_result and getattr(worm_result, "retention_errors", None):
        # Retention is an attribute. It is a hard error only where the operator's
        # policy demands custody, and otherwise it is surfaced as a warning so a
        # reader can see the position without the receipt being failed for it.
        if getattr(trust_policy, "require_retention", False):
            errors.extend(worm_result.retention_errors)
        else:
            warnings.extend(worm_result.retention_errors)

    return VerifyResult(
        bundle_path=bundle_path,
        valid=len(errors) == 0,
        grade=grade,
        events=events,
        chain_result=chain_result,
        ledger_result=ledger_result,
        manifest_result=manifest_result,
        timestamp_result=timestamp_result,
        worm_result=worm_result,
        errors=errors,
        warnings=warnings,
    )
