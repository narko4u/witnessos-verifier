# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Anchor coverage: what a checkpoint actually covers, and what it does not.

A bundle is the current history of a case. An anchor is a commitment made at one
moment over a subset of that history. Those are two different objects and they
stop being the same object the instant a case grows after being anchored.

This module models the second object explicitly. A coverage record names one
case, one batch, one exact event set, one sequence interval, one Merkle root and
one external timestamp. Verification recomputes the root from the events the
bundle actually contains, so `covered_event_ids` is never trusted as metadata:
if the list disagrees with the range, with the events, or with the root, the
coverage does not authenticate and cannot elevate anything.

`anchor_coverage_version` 1 is the only schema understood here. A bundle written
before this model existed carries a single token over the manifest root and no
coverage directory; that case is resolved into one implicit coverage record only
when the signed manifest proves the whole event set unambiguously. Guessing is
never an option, and anything ambiguous caps at E3.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .merkle import build_merkle_tree, leaf_hash
from .timestamp import verify_timestamp

ANCHOR_COVERAGE_VERSION = 1
COVERAGE_DIR = "anchor"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED = (
    "anchor_coverage_version",
    "checkpoint_id",
    "case_id",
    "batch_id",
    "first_seq",
    "last_seq",
    "covered_event_ids",
    "covered_root",
    "finalised_at",
    "tsa",
)


class CoverageError(Exception):
    """A coverage record that cannot be parsed or is structurally invalid."""


@dataclass(frozen=True)
class CoverageRecord:
    checkpoint_id: str
    case_id: str
    batch_id: str
    first_seq: int
    last_seq: int
    covered_event_ids: Tuple[str, ...]
    covered_root: str
    finalised_at: str
    token_file: str
    imprint: str = ""
    trust_reference: str = ""
    gen_time: str = ""
    implicit: bool = False
    source: str = ""


@dataclass
class CoverageResult:
    """What could be established about one coverage record.

    `authenticated` is the only field that may elevate a grade. It requires every
    fact below to hold at once: the record is well formed, it names this case, its
    ids and range agree, the root recomputed from the covered events matches the
    committed root, the token authenticates that root on an accepted trust path,
    and the checkpoint does not precede the batch it anchors.
    """

    record: Optional[CoverageRecord] = None
    authenticated: bool = False
    anchored_ids: frozenset = frozenset()
    root_recomputed: bool = False
    token_valid: bool = False
    trust_verified: bool = False
    ordering_ok: bool = False
    errors: List[str] = field(default_factory=list)
    attributes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        record = self.record
        if record is None:
            return "no coverage record"
        return (
            f"{record.checkpoint_id} covers {len(self.anchored_ids)} event(s) "
            f"seq {record.first_seq}-{record.last_seq}"
        )


def _instant(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def load_records(bundle_path: Path, manifest=None, events: Sequence = ()) -> Tuple[List[CoverageRecord], List[str]]:
    """Every coverage record the bundle offers, explicitly or by legacy proof.

    Returns (records, errors). A malformed record is an error and never a skipped
    file: an operator cannot make a checkpoint disappear by corrupting its JSON.
    """
    errors: List[str] = []
    records: List[CoverageRecord] = []
    directory = bundle_path / COVERAGE_DIR
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                records.append(_parse_record(json.loads(path.read_text()), source=path.name))
            except (OSError, ValueError, CoverageError) as exc:
                errors.append(f"Anchor coverage {path.name}: {exc}")
    if records or errors:
        return records, errors
    legacy = _legacy_record(bundle_path, manifest, events)
    if legacy is not None:
        records.append(legacy)
    return records, errors


def _parse_record(data: dict, source: str = "") -> CoverageRecord:
    if not isinstance(data, dict):
        raise CoverageError("not a JSON object")
    for key in _REQUIRED:
        if key not in data:
            raise CoverageError(f"missing '{key}'")
    version = data["anchor_coverage_version"]
    if version != ANCHOR_COVERAGE_VERSION:
        raise CoverageError(f"unsupported anchor_coverage_version {version!r}")
    tsa = data["tsa"]
    if not isinstance(tsa, dict) or not tsa.get("token_file"):
        raise CoverageError("tsa.token_file is required")
    ids = data["covered_event_ids"]
    if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or not i for i in ids):
        raise CoverageError("covered_event_ids must be a non-empty list of event ids")
    if len(set(ids)) != len(ids):
        raise CoverageError("covered_event_ids contains duplicates")
    first_seq, last_seq = data["first_seq"], data["last_seq"]
    if type(first_seq) is not int or type(last_seq) is not int or first_seq > last_seq:
        raise CoverageError("first_seq/last_seq must be integers with first_seq <= last_seq")
    root = str(data["covered_root"]).strip().lower()
    if not _HEX64.match(root):
        raise CoverageError("covered_root must be 64 lowercase hex characters")
    if not isinstance(data["finalised_at"], str):
        raise CoverageError("finalised_at must be a timestamp string")
    return CoverageRecord(
        checkpoint_id=str(data["checkpoint_id"]),
        case_id=str(data["case_id"]),
        batch_id=str(data["batch_id"]),
        first_seq=first_seq,
        last_seq=last_seq,
        covered_event_ids=tuple(ids),
        covered_root=root,
        finalised_at=data["finalised_at"],
        token_file=str(tsa["token_file"]),
        imprint=str(tsa.get("imprint") or "").strip().lower(),
        trust_reference=str(tsa.get("trust_reference") or ""),
        gen_time=str(tsa.get("gen_time") or ""),
        source=source,
    )


def _legacy_record(bundle_path: Path, manifest, events: Sequence) -> Optional[CoverageRecord]:
    """The pre-coverage shape: one token over the manifest root, whole event set.

    Only produced when the signed manifest already commits to exactly these events,
    which is what makes "the token covers all of them" a proof rather than a guess.
    """
    if manifest is None:
        return None
    directory = bundle_path / "timestamp"
    if not directory.is_dir():
        return None
    tokens = sorted(directory.glob("*.tsr")) + sorted(directory.glob("*.der"))
    if len(tokens) != 1:
        return None
    ids = tuple(manifest.event_ids)
    if not ids:
        return None
    if events and {e.event_id for e in events} != set(ids):
        return None
    return CoverageRecord(
        checkpoint_id=f"implicit:{manifest.batch_id}",
        case_id=manifest.case_id,
        batch_id=manifest.batch_id,
        first_seq=manifest.start_seq,
        last_seq=manifest.end_seq,
        covered_event_ids=ids,
        covered_root=manifest.root,
        finalised_at=manifest.signed_at,
        token_file=f"timestamp/{tokens[0].name}",
        implicit=True,
        source="batch manifest",
    )


def verify_coverage(
    record: CoverageRecord,
    events: Sequence,
    bundle_path: Path,
    policy=None,
    tsa_url: Optional[str] = None,
    manifest_case_id: Optional[str] = None,
) -> CoverageResult:
    """Authenticate one coverage record against the events the bundle actually holds."""
    result = CoverageResult(record=record)
    by_id = {event.event_id: event for event in events}
    by_seq: Dict[int, object] = {}
    for event in events:
        by_seq.setdefault(int(event.seq), event)

    if manifest_case_id is not None and record.case_id != manifest_case_id:
        result.errors.append(
            f"coverage belongs to case {record.case_id}, not {manifest_case_id}"
        )
        return result

    declared = set(record.covered_event_ids)
    in_range = {
        event.event_id
        for event in events
        if record.first_seq <= int(event.seq) <= record.last_seq
    }
    if declared != in_range:
        missing = sorted(in_range - declared)
        outside = sorted(declared - in_range)
        detail = []
        if missing:
            detail.append(f"{len(missing)} event(s) inside the declared range are not covered: {', '.join(missing[:4])}")
        if outside:
            detail.append(f"{len(outside)} covered id(s) fall outside the declared range: {', '.join(outside[:4])}")
        result.errors.append(
            "covered event ids and sequence range disagree" + (": " + "; ".join(detail) if detail else "")
        )
        return result

    covered = [by_id[event_id] for event_id in record.covered_event_ids if event_id in by_id]
    if len(covered) != len(record.covered_event_ids):
        absent = [event_id for event_id in record.covered_event_ids if event_id not in by_id]
        result.errors.append(
            "coverage names events the bundle does not contain: " + ", ".join(absent[:4])
        )
        return result

    leaves = [leaf_hash(event.canonical_bytes) for event in sorted(covered, key=lambda e: int(e.seq))]
    recomputed = build_merkle_tree(leaves).hex()
    if recomputed != record.covered_root:
        result.errors.append(
            "covered events do not reproduce the committed root; the coverage list or the "
            "evidence was altered after anchoring"
        )
        return result
    result.root_recomputed = True

    expected = hashlib.sha256(bytes.fromhex(record.covered_root)).digest()
    if record.imprint and record.imprint != expected.hex():
        result.errors.append("declared imprint is not the digest of the covered root")
        return result

    token_path = (bundle_path / record.token_file).resolve()
    try:
        token_path.relative_to(bundle_path.resolve())
    except ValueError:
        result.errors.append("timestamp token path escapes the bundle")
        return result
    if not token_path.is_file():
        result.errors.append(f"timestamp token not found: {record.token_file}")
        return result

    timestamp = verify_timestamp(token_path, expected, policy, tsa_url)
    result.token_valid = bool(timestamp.valid and timestamp.imprint_matches)
    result.trust_verified = bool(getattr(timestamp, "trust_verified", False))
    if not result.token_valid:
        result.errors.append("timestamp token does not authenticate this coverage")
        return result
    if not result.trust_verified:
        result.errors.append(
            "timestamp token is well formed but its trust path was not accepted, so the "
            "checkpoint is not authenticated"
        )
        return result

    gen_time = _instant(getattr(timestamp.tst_info, "gen_time", None))
    finalised = _instant(record.finalised_at)
    if gen_time is None or finalised is None:
        result.errors.append("coverage ordering could not be established from the token clock")
        return result
    if gen_time < finalised:
        result.errors.append(
            f"checkpoint precedes the batch it anchors ({gen_time.isoformat()} < "
            f"{finalised.isoformat()})"
        )
        return result
    result.ordering_ok = True

    result.anchored_ids = frozenset(record.covered_event_ids)
    result.authenticated = True
    if record.implicit:
        result.attributes.append(
            "Legacy evidence: coverage was proven from the signed batch manifest, not from "
            "an explicit coverage record"
        )
    return result


def qualifying_chain(action_event, ack_event, events: Sequence) -> frozenset:
    """The evidence that has to sit under one anchor for an action to reach E4.

    The action and the acknowledgement are the ends; everything recorded between
    them is the enforcement trail the grade depends on. An anchor that carries the
    acknowledgement but not the action it corroborates is not coverage, and an
    anchor that carries the action but not the corroboration is not E3 either.
    """
    low, high = sorted((int(action_event.seq), int(ack_event.seq)))
    ids = {
        event.event_id
        for event in events
        if low <= int(event.seq) <= high
    }
    ids.add(action_event.event_id)
    ids.add(ack_event.event_id)
    return frozenset(ids)
