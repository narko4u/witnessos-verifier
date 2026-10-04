# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Signed batch manifest verification.

Batch manifests record all events in a batch and are signed by
the batch signing key. The manifest signature proves the batch
was produced by an authorised WitnessOS instance.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .key_registry import KeyRegistry
from .signatures import UnsupportedScheme, verify_signature


class ManifestError(Exception):
    """Manifest verification error."""


@dataclass
class BatchManifest:
    batch_id: str
    signing_key_id: str
    case_id: str
    root: str
    prev_root: str
    event_ids: List[str]
    start_seq: int
    end_seq: int
    signed_at: str
    signature: str
    signature_suite: str = None
    countersigner_key_id: str = None
    countersignature: str = None

    @property
    def is_composite(self) -> bool:
        """A manifest declares a suite or it does not. There is no third state."""
        return self.signature_suite is not None

    @property
    def suite_labels(self) -> List[str]:
        """The lowercase scheme labels the suite names, in declaration order."""
        if not self.signature_suite:
            return []
        return [p.strip().lower() for p in str(self.signature_suite).split("+") if p.strip()]

    @classmethod
    def from_file(cls, path: Path) -> "BatchManifest":
        if not path.exists():
            raise ManifestError(f"Manifest file not found: {path}")

        data = json.loads(path.read_text())
        required = ["batch_id", "signing_key_id", "root", "event_ids",
                    "start_seq", "end_seq", "signed_at", "signature"]
        for field_name in required:
            if field_name not in data:
                raise ManifestError(f"Missing required field '{field_name}' in manifest")

        return cls(
            batch_id=data["batch_id"],
            signing_key_id=data["signing_key_id"],
            case_id=data.get("case_id", ""),
            root=data["root"],
            prev_root=data.get("prev_root", ""),
            event_ids=data["event_ids"],
            start_seq=data["start_seq"],
            end_seq=data["end_seq"],
            signed_at=data["signed_at"],
            signature=data["signature"],
            signature_suite=data.get("signature_suite"),
            countersigner_key_id=data.get("countersigner_key_id"),
            countersignature=data.get("countersignature"),
        )

    @property
    def signed_data(self) -> bytes:
        """The data that was signed to produce the manifest signature.

        A version 1 manifest produces exactly the bytes it always did, so every
        manifest written before the suite dimension existed keeps its exact meaning.

        A composite manifest additionally covers the suite declaration and the
        counter key id. The declaration has to be inside the signed bytes: if it sat
        beside them, the counter half and the declaration could be removed together
        and the remaining classical signature would still verify over content that
        had never changed, producing a record that looks like a version 1 manifest
        and is accepted as one. The signatures themselves are never signed.
        """
        obj = {
            "batch_id": self.batch_id,
            "signing_key_id": self.signing_key_id,
            "case_id": self.case_id,
            "root": self.root,
            "prev_root": self.prev_root,
            "event_ids": self.event_ids,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "signed_at": self.signed_at,
        }
        if self.is_composite:
            obj["signature_suite"] = self.signature_suite
            obj["countersigner_key_id"] = self.countersigner_key_id
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ManifestResult:
    valid: bool
    manifest: BatchManifest
    key_found: bool
    key_valid: bool
    signature_valid: bool
    errors: List[str]
    signature_suite: str = ""
    countersignature_valid: bool = True


def _verify_half(algorithm, public_key_hex, message, signature_b64, errors, label) -> bool:
    """Verify one half, turning an unperformable scheme into a named refusal.

    UnsupportedScheme is caught here and never allowed to escape. A suite this build
    cannot perform is a failed verification with a reason, not a skip and not a
    traceback. Reading an unperformable suite as the half we can perform is the
    downgrade this whole path exists to prevent.
    """
    try:
        if not verify_signature(algorithm, public_key_hex, message, signature_b64):
            errors.append(f"{label} invalid for scheme {algorithm}")
            return False
        return True
    except UnsupportedScheme as exc:
        errors.append(f"{label}: unsupported signature scheme {exc}")
        return False


def verify_manifest(manifest: BatchManifest, key_registry: KeyRegistry) -> ManifestResult:
    """Verify a batch manifest signature, composite or not.

    A version 1 manifest takes the original path and produces the original verdict,
    byte for byte. A manifest declaring a signature suite takes the composite path,
    where both halves must verify or the manifest fails.
    """
    errors = []

    key = key_registry.get_key(manifest.signing_key_id)
    if key is None:
        return ManifestResult(
            valid=False,
            manifest=manifest,
            key_found=False,
            key_valid=False,
            signature_valid=False,
            errors=[f"Key {manifest.signing_key_id} not found in key registry"],
        )

    if not key.is_valid:
        errors.append(f"Key {manifest.signing_key_id} is {key.status}")

    suite = manifest.signature_suite or ""
    labels = manifest.suite_labels
    counter_key = None

    if manifest.is_composite:
        # Refusal 1: a suite with no counter half is a claim with nothing behind it.
        if not manifest.countersignature:
            errors.append(
                "Manifest declares signature suite %s but carries no countersignature" % suite
            )
        # Refusal 5: a suite must name the key that countersigns.
        if not manifest.countersigner_key_id:
            errors.append(
                "Manifest declares signature suite %s but names no countersigner key" % suite
            )
        # Refusal 3a: a one-scheme suite is a single-scheme record written the long way.
        if len(labels) < 2:
            errors.append(
                "Manifest declares signature suite %s, which names fewer than two schemes" % suite
            )
        if manifest.countersigner_key_id:
            counter_key = key_registry.get_key(manifest.countersigner_key_id)
            if counter_key is None:
                errors.append(
                    f"Countersigner key {manifest.countersigner_key_id} not found in key registry"
                )
            elif not counter_key.is_valid:
                errors.append(
                    f"Countersigner key {manifest.countersigner_key_id} is {counter_key.status}"
                )
            elif counter_key.public_key_hex == key.public_key_hex:
                errors.append("Countersigner key is the primary key")
    elif manifest.countersignature:
        # Refusal 2: a counter half with no suite cannot be interpreted.
        errors.append("Manifest carries a countersignature but declares no signature suite")

    # Refusal 4: the suite must agree with the algorithms the keys themselves declare.
    # This is what closes the swap: a signature from a different key carries a
    # different declared algorithm, so the two sets stop matching.
    if manifest.is_composite and counter_key is not None:
        present = {
            str(key.algorithm).strip().lower(),
            str(counter_key.algorithm).strip().lower(),
        }
        if present != set(labels):
            errors.append(
                "Manifest declares signature suite %s but its keys declare %s"
                % (suite, " and ".join(sorted(present)))
            )

    # Refusal 3 and refusal 6 travel through _verify_half.
    sig_valid = _verify_half(
        key.algorithm, key.public_key_hex, manifest.signed_data, manifest.signature,
        errors, f"Manifest signature for key {manifest.signing_key_id}",
    )

    counter_valid = True
    if manifest.is_composite and counter_key is not None and manifest.countersignature:
        counter_valid = _verify_half(
            counter_key.algorithm, counter_key.public_key_hex, manifest.signed_data,
            manifest.countersignature, errors,
            f"Manifest countersignature for key {manifest.countersigner_key_id}",
        )

    return ManifestResult(
        valid=len(errors) == 0,
        manifest=manifest,
        key_found=True,
        key_valid=key.is_valid,
        signature_valid=sig_valid and counter_valid,
        errors=errors,
        signature_suite=suite,
        countersignature_valid=counter_valid,
    )
