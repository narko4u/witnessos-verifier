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
import os
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .binding import verify_event_signatures, verify_batch_binding
from .case_chain import verify_case_chain, ChainResult
from .anchor_coverage import load_records, qualifying_chain, verify_coverage
from .appraisal import PRIMARY_ACTION_TYPES
from . import provider_attestation as pa
from .corroboration import CorroborationResult, assess_actions, assess_corroboration
from .events import load_events, Event, EventError
from .evidence_semantics import enforcement_observed, observation_external, observer_identity
from .grades import derive_action_grades, derive_grade, Grade, GradeResult
from .key_registry import KeyRegistry, KeyRegistryError
from .ledger import verify_ledger_sequence, LedgerResult
from .manifest import BatchManifest, verify_manifest, ManifestResult
from .timestamp import verify_timestamp, TimestampResult
from .worm import verify_worm_bundle, WormResult


def _utc_instant(value) -> Optional[datetime]:
    """Parse an RFC 3161 genTime or a manifest signed_at into an aware UTC instant.

    Returns None rather than guessing when the value is absent, naive or malformed:
    an unparseable time is not evidence of a temporal violation.
    """
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


logger = logging.getLogger(__name__)

PROVIDER_ACK_TYPES = frozenset({"provider.acknowledged", "provider.confirmed",
                                "provider_acknowledged", "provider_confirmed"})


class VerifyError(Exception):
    """Top-level verification error."""


_TRUST_POLICY_WORDS = (
    "allowlist",
    "not trusted",
    "untrusted",
    "trusted root",
    "trust anchor",
    "revocation",
    "revoked",
    "crl",
    "not yet valid",
    "expired",
    "tsa url",
)


def _anchor_policy_only(errors) -> bool:
    """True when every anchor error is the operator's trust judgement.

    A token that commits to our root and parses correctly is evidence a root
    existed at a time. Whether the signer is one this operator believes is a
    policy question, and it belongs in the cap reason, not in the verdict. A token
    that fails its own signature or imprint is damaged, and damaged evidence stays
    a hard failure no matter what the policy says.
    """
    if not errors:
        return False
    for message in errors:
        text = str(message).lower()
        if "signature" in text or "imprint" in text:
            return False
        if not any(word in text for word in _TRUST_POLICY_WORDS):
            return False
    return True


def _rung_of(item: str) -> Optional[int]:
    """The rung a requirement line belongs to, or None when it is not a rung.

    Attributes are not rungs: retention custody rides along a receipt and never
    moves the grade, so a missing attribute must never be quoted as the reason the
    ladder stopped.
    """
    if not isinstance(item, str):
        return None
    text = item.strip()
    if text.lower().startswith("attribute:") or "attribute" in text.split(":")[0].lower():
        return None
    match = re.match(r"^E([0-4])(?![0-9])", text)
    return int(match.group(1)) if match else None


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
    corroboration: Optional[CorroborationResult] = None
    timestamp_result: Optional[TimestampResult] = None
    worm_result: Optional[WormResult] = None
    action_grades: dict = field(default_factory=dict)
    action_basis: dict = field(default_factory=dict)
    action_reasons: dict = field(default_factory=dict)
    subject_action_id: Optional[str] = None
    anchor_coverages: List[object] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    profile: str = "foundation"

    @property
    def grade_cap_reason(self) -> str:
        """Why the verdict stopped where it did, in the profile's own words."""
        return getattr(self.grade, "cap_reason", "") if self.grade else "" 

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


def _point_at_provider_records(bundle_path):
    """Point the adapter at this bundle's frozen provider objects, and remember
    what was there before so one verification cannot leak into the next."""
    previous = os.environ.get(pa.PROVIDER_RECORDS_ENV)
    records_dir = Path(bundle_path) / "provider_records"
    if records_dir.is_dir():
        os.environ[pa.PROVIDER_RECORDS_ENV] = str(records_dir)
    else:
        os.environ.pop(pa.PROVIDER_RECORDS_ENV, None)
    return previous


def _restore_provider_records(previous) -> None:
    if previous is None:
        os.environ.pop(pa.PROVIDER_RECORDS_ENV, None)
    else:
        os.environ[pa.PROVIDER_RECORDS_ENV] = previous


def verify(bundle_path: Path, alpha_mode: bool = False, *, trust_policy=None, tsa_url=None,
           expected_nonce=None, subject_action_id: Optional[str] = None,
           profile: str = "foundation") -> VerifyResult:
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
    manifest = None
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

    # 6. Appraise corroboration. An event type is a claim, so the verifier asks
    #    whether an independently identified party signed an acknowledgement that
    #    names its own record and is bound to this action and this batch. A
    #    bundled key, a provider name and a custody label establish none of that.
    previous_records = _point_at_provider_records(bundle_path)
    corroboration = assess_corroboration(events, key_registry, manifest, trust_policy)
    action_pairs = assess_actions(events, key_registry, manifest, trust_policy)
    # The vendor-level verdict, with its own codes, so an auditor reads
    # "provider_amount_mismatch" rather than "corroboration failed".
    substantive: dict = {}
    for ack_event in events:
        if ack_event.event_type not in PROVIDER_ACK_TYPES:
            continue
        att = (ack_event.payload or {}).get("provider_corroboration")
        if not isinstance(att, dict):
            continue
        subject = next(
            (e for e in events if e.event_id == str(att.get("action_event_id"))), None
        )
        ok, reasons = pa.substantive_check(
            att,
            {"payload": dict(subject.payload or {})} if subject is not None else None,
            pa.load_provider_records(),
        )
        substantive[ack_event.event_id] = [] if ok else list(reasons)
    _restore_provider_records(previous_records)
    if corroboration.present and not corroboration.satisfied:
        warnings.append(f"Corroboration not established: {corroboration.summary()}")

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
    # An authenticated token that predates the batch it is paired with proves the
    # commitment existed before the batch did, which is the opposite of anchoring.
    # A token that failed to verify leaves timestamp_result None, which is
    # indistinguishable from a bundle that never carried one. The grade text has to
    # tell those apart, so presence is decided by the files, not by the verdict.
    anchor_present = ts_dir.exists() and any(ts_dir.glob("*.tsr")) or any(ts_dir.glob("*.der"))

    if timestamp_result is not None and getattr(timestamp_result, "tst_info", None) is not None:
        gen_instant = _utc_instant(timestamp_result.tst_info.gen_time)
        signed_instant = _utc_instant(getattr(manifest, "signed_at", None))
        if gen_instant is not None and signed_instant is not None:
            if gen_instant < signed_instant:
                errors.append(
                    "Checkpoint precedes the batch it anchors: the token was minted "
                    f"({timestamp_result.tst_info.gen_time}) before the batch claims to "
                    f"have been finalised ({manifest.signed_at})"
                )
        else:
            warnings.append(
                "Could not compare checkpoint time to batch finalisation time; "
                "anchor ordering was not established"
            )

    # Coverage is a different property from bundle integrity. The bundle is the
    # current history; an anchor is a commitment made over a subset of it at one
    # moment. Appending an event therefore neither inherits the old anchor nor
    # invalidates it, and each action is graded against the coverage that actually
    # contains its qualifying chain.
    coverage_records, coverage_errors = load_records(bundle_path, manifest, events)
    errors.extend(coverage_errors)
    coverage_results = []
    for record in coverage_records:
        try:
            coverage_results.append(
                verify_coverage(
                    record,
                    events,
                    bundle_path,
                    trust_policy,
                    tsa_url,
                    manifest.case_id if manifest is not None else None,
                )
            )
        except Exception as exc:  # a coverage that cannot be checked is not coverage
            errors.append(f"Anchor coverage {record.checkpoint_id}: {exc}")
    for coverage in coverage_results:
        if not coverage.authenticated:
            for detail in coverage.errors[:2]:
                warnings.append(f"Anchor {coverage.record.checkpoint_id}: {detail}")

    integrity = derive_grade(
        events_loaded=events_loaded,
        chain_result=chain_result,
        ledger_result=ledger_result,
        manifest_result=manifest_result,
        corroboration=None,
        timestamp_result=None,
        # Presence is a fact about the bundle, not about the verdict: a token that
        # failed to verify and a bundle that never carried one must not produce the
        # same cap text.
        anchor_present=anchor_present,
        worm_result=worm_result,
        alpha_mode=False,
        event_signatures_valid=not signature_errors,
        batch_binding_valid=(
            manifest_result is not None
            and not any(not e.startswith("Merkle proof:") for e in binding_errors)
            and (
                profile != "foundation"
                or not any(e.startswith("Merkle proof:") for e in binding_errors)
            )
        ),
        merkle_proof_valid=manifest_result is not None and not any(e.startswith("Merkle proof:") for e in binding_errors),
        observation_external=observation_external(events, key_registry),
        enforcement_observed=enforcement_observed(events, key_registry),
        require_retention=bool(getattr(trust_policy, "require_retention", False)),
        require_observer_identity=bool(
            getattr(trust_policy, "require_observer_identity", False)
        ),
        observer_identity=observer_identity(
            events,
            getattr(trust_policy, "observer_keys", None),
            key_registry,
        ),
        profile=profile,
    )

    # The governed action is the one that proceeded, not every dispatch step that
    # carried it there: those steps belong inside the qualifying chain. An
    # acknowledgement also names its own subject, and a record set that models an
    # action as a dispatch still has an action to grade, so both sources count.
    named_actions = set(action_pairs)
    action_events = [
        event
        for event in sorted(events, key=lambda e: int(e.seq))
        if event.event_type in PRIMARY_ACTION_TYPES or event.event_id in named_actions
    ]
    action_result = derive_action_grades(
        action_events=action_events,
        action_corroboration=action_pairs,
        coverage_results=coverage_results,
        integrity_grade=integrity.grade,
        chain_of=lambda action, ack: qualifying_chain(action, ack, events),
        subject_action_id=subject_action_id,
    )

    grade_value = action_result.evidence_grade
    if alpha_mode and grade_value == Grade.E4:
        grade_value = Grade.E3
        action_result.requirements_met.append("Alpha: E4 evidence present (capped at E3)")
    # The profile's own words travel with the verdict. Rebuilding the grade here
    # would otherwise drop the reason a Foundation gate stopped the ladder, and a
    # cap without a reason is indistinguishable from a permissive pass.
    #
    # A cap must name the rung that actually stopped the ladder. Two sources can
    # disagree: the bundle-level integrity grade and the action-level grade. When
    # the action grade is the higher one, a missing item belonging to a rung the
    # verdict already passed is stale, and quoting it reads as a contradiction
    # ("capped at E3: E3: no corroboration was appraised" on a corroborated
    # record). Rung-filter both the reason and the missing list.
    combined_met = list(integrity.requirements_met) + list(action_result.requirements_met)
    combined_missing = list(integrity.requirements_missing) + list(action_result.requirements_missing)
    awarded_rung = _rung_of(str(grade_value))
    met_rungs = {_rung_of(item) for item in combined_met}
    stale = {
        item
        for item in combined_missing
        if _rung_of(item) and _rung_of(item) <= awarded_rung and _rung_of(item) in met_rungs
    }
    combined_missing = [item for item in combined_missing if item not in stale]
    ahead = [
        item
        for item in combined_missing
        if _rung_of(item) is not None and _rung_of(item) > awarded_rung
    ]
    cap_reason = getattr(integrity.grade, "cap_reason", "") or ""
    if cap_reason and stale:
        cap_reason = ""
    if not cap_reason and ahead:
        cap_reason = f"capped at {grade_value}: {ahead[0]}"
    grade = GradeResult(
        grade=grade_value,
        display=action_result.display(),
        requirements_met=combined_met,
        requirements_missing=combined_missing,
        cap_reason=cap_reason,
    )

    # Collect all errors
    if chain_result and chain_result.errors:
        errors.extend(chain_result.errors)
    if ledger_result and ledger_result.errors:
        errors.extend(ledger_result.errors)
    if manifest_result and manifest_result.errors:
        errors.extend(manifest_result.errors)
    if timestamp_result and timestamp_result.errors:
        # An anchor that commits to our root but whose issuer chain this policy does
        # not accept is a trust judgement, not damaged evidence: the token proves a
        # root existed at a time, the operator decides whether to believe the signer.
        # Failing the artefact outright would make E3 unobservable, since export
        # refuses an unanchored case. Cap at E3 and say why, keep the errors visible
        # as warnings. A token that does not match the imprint is damaged and fatal.
        if (
            timestamp_result.imprint_matches
            and not timestamp_result.trust_verified
            and _anchor_policy_only(timestamp_result.errors)
        ):
            warnings.extend(timestamp_result.errors)
        else:
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
        corroboration=corroboration,
        timestamp_result=timestamp_result,
        worm_result=worm_result,
        action_grades=dict(action_result.action_grades),
        action_reasons={
            **{
                str(action_id): list(getattr(result, 'reasons', ()) or ())
                for action_id, (_ack, result) in (action_pairs or {}).items()
            },
            **{f"substantive:{key}": value for key, value in substantive.items()},
        },
        action_basis=dict(action_result.basis),
        subject_action_id=action_result.subject_action_id,
        anchor_coverages=coverage_results,
        errors=errors,
        warnings=warnings,
        profile=profile,
    )
