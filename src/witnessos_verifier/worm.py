# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WORM evidence bundle verification.

Verifies that WORM-stored evidence bundles have not been tampered with.
Each bundle contains a canonical hash that is compared against what
was recorded at storage time.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


class WormError(Exception):
    """WORM store verification error."""


@dataclass
class WormBundle:
    """A WORM evidence bundle record."""
    batch_id: str
    stored_hash: str
    stored_at: str
    case_id: str
    file_count: int
    file_hashes: Dict[str, str]


@dataclass
class WormResult:
    valid: bool
    bundle: WormBundle
    hash_matches: bool
    file_count_matches: bool
    errors: List[str]
    retention_verified: bool = False
    retention_errors: List[str] = field(default_factory=list)


def load_worm_bundle(worm_dir: Path) -> WormBundle:
    """Load a WORM evidence bundle from a directory."""
    store_file = worm_dir / "batch_store.json"
    if not store_file.exists():
        raise WormError(f"WORM store file not found: {store_file}")

    data = json.loads(store_file.read_text())
    return WormBundle(
        batch_id=data["batch_id"],
        stored_hash=data["stored_hash"],
        stored_at=data["stored_at"],
        case_id=data.get("case_id", ""),
        file_count=data.get("file_count", 0),
        file_hashes=data.get("file_hashes", {}),
    )


def verify_worm_bundle(worm_dir: Path, evidence_dir: Path, policy=None, timestamp_result=None) -> WormResult:
    """Verify a WORM evidence bundle against the original evidence.

    Checks:
    1. The WORM bundle file exists
    2. The stored hash matches the current evidence
    3. The file count matches
    """
    errors = []

    try:
        bundle = load_worm_bundle(worm_dir)
    except WormError as e:
        return WormResult(valid=False, bundle=None, hash_matches=False,
                          file_count_matches=False, errors=[str(e)])

    # Compute hash of all evidence files (excluding worm dir itself)
    evidence_files = sorted(evidence_dir.rglob("*"))
    computed_hash = hashlib.sha256()

    for f in evidence_files:
        if f.is_file() and f.relative_to(evidence_dir).parts[0] != "worm":
            computed_hash.update(f.read_bytes())

    current_hash = computed_hash.hexdigest()
    hash_ok = current_hash == bundle.stored_hash

    if not hash_ok:
        errors.append(
            f"WORM hash mismatch: stored={bundle.stored_hash[:16]}..., "
            f"current={current_hash[:16]}..."
        )

    # Count files (excluding worm dir)
    current_count = sum(1 for f in evidence_files if f.is_file() and f.relative_to(evidence_dir).parts[0] != "worm")
    count_ok = current_count == bundle.file_count

    if not count_ok:
        errors.append(
            f"File count mismatch: stored={bundle.file_count}, "
            f"current={current_count}"
        )

    retention_ok, retention_errors = verify_retention(worm_dir, evidence_dir, policy, timestamp_result)

    # Retention is reported as an attribute, never folded into the store verdict.
    # docs/CUSTODY.md 7: the attribute is recorded and require_retention=True
    # demands it, and retention never moves the grade. Keeping these out of
    # `errors` is what lets a two-party receipt be E4-clean on the cryptography
    # alone, while a caller that requires custody still reads the reason in
    # retention_errors.

    return WormResult(
        valid=len(errors) == 0,
        bundle=bundle,
        hash_matches=hash_ok,
        file_count_matches=count_ok,
        errors=errors,
        retention_verified=retention_ok,
        retention_errors=retention_errors,
    )


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')


def snapshot_inventory(evidence_dir):
    """Version 1 inventory binds relative filenames, byte lengths and file hashes.

    Excludes only the top-level worm/ control directory to avoid circular
    receipt/checksum inputs. Everything else, including the TSA token, is bound.
    """
    files = {}
    for p in sorted(evidence_dir.rglob('*')):
        if p.is_symlink():
            raise WormError('Symlinks are not permitted in retained snapshots')
        if p.is_file() and p.relative_to(evidence_dir).parts[0] != 'worm':
            raw = p.read_bytes()
            files[p.relative_to(evidence_dir).as_posix()] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return {'schema': 'witnessos-snapshot-v1', 'files': files}


def verify_retention(worm_dir, evidence_dir, policy, timestamp_result, *, now=None):
    """Authenticate a storage custodian's signed compliance-retention receipt.

    The operator must pin an independent custodian's Ed25519 public key outside
    the bundle. A timestamp by itself proves existence, never retention. This
    check proves that the trusted custodian attested retention of this exact
    snapshot/version; it cannot prove a custodian never lies or loses storage.
    """
    from datetime import datetime, timezone, timedelta
    from .signatures import verify_detached_signature
    from .trust_policy import parse_utc

    receipt_path = worm_dir / 'retention.json'
    if not receipt_path.exists():
        return False, ['Authenticated retention missing: supply worm/retention.json signed by an independently trusted storage custodian']
    try:
        def unique(pairs):
            data = {}
            for key, value in pairs:
                if key in data:
                    raise ValueError('Duplicate receipt field')
                data[key] = value
            return data
        receipt = json.loads(receipt_path.read_text(), object_pairs_hook=unique)
        fields = {'schema', 'authority', 'batch_id', 'case_id', 'merkle_root', 'snapshot_sha256',
                  'object_uri', 'version_id', 'retention_mode', 'issued_at', 'retain_until', 'signature'}
        if not isinstance(receipt, dict) or set(receipt) != fields:
            raise ValueError('Invalid retention receipt schema/fields')
        if any(not isinstance(v, str) or not v for v in receipt.values()):
            raise ValueError('Retention receipt fields must be nonempty strings')
        if receipt['schema'] != 'witnessos-retention-v1' or receipt['retention_mode'] != 'COMPLIANCE':
            raise ValueError('Unsupported retention schema or mode')
        authority_key = policy.retention_authorities.get(receipt['authority']) if policy else None
        if not authority_key:
            raise ValueError('Retention authority is not independently trusted')
        registry = json.loads((evidence_dir / 'keys.json').read_text())
        records = registry if isinstance(registry, list) else registry.get('keys', [])
        if any(bytes.fromhex(k['public_key_hex']) == bytes.fromhex(authority_key) for k in records):
            raise ValueError('Retention authority must be independent of bundle signing keys')
        signed = {k: v for k, v in receipt.items() if k != 'signature'}
        if not verify_detached_signature(authority_key, canonical_json(signed), receipt['signature']):
            raise ValueError('Retention receipt signature invalid')
        manifest = json.loads((evidence_dir / 'batch_manifest.json').read_text())
        if any(receipt[k] != manifest[m] for k, m in [('batch_id', 'batch_id'), ('case_id', 'case_id'), ('merkle_root', 'root')]):
            raise ValueError('Retention receipt belongs to a different signed batch')
        digest = hashlib.sha256(canonical_json(snapshot_inventory(evidence_dir))).hexdigest()
        if receipt['snapshot_sha256'] != digest:
            raise ValueError('Retention snapshot digest mismatch')
        if not timestamp_result or not (timestamp_result.valid and timestamp_result.signature_verified and timestamp_result.trust_verified):
            raise ValueError('Retention snapshot requires a verified external timestamp')
        now = now or datetime.now(timezone.utc)
        issued = parse_utc(receipt['issued_at'])
        until = parse_utc(receipt['retain_until'])
        anchored = parse_utc(timestamp_result.tst_info.gen_time)
        if policy.clock_tolerance < 0 or policy.minimum_retention_seconds < 0:
            raise ValueError('Invalid retention time policy')
        tolerance = timedelta(seconds=policy.clock_tolerance)
        if issued > now + tolerance or issued < anchored - tolerance:
            raise ValueError('Retention receipt issue time inconsistent with anchored snapshot')
        if until <= issued or until <= now + timedelta(seconds=policy.minimum_retention_seconds):
            raise ValueError('Retention expired or shorter than required policy')
        return True, []
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return False, [f'Authenticated retention: {exc}']
