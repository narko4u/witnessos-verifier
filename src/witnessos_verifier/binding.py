# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Bind every event to its signature and the signed batch commitment."""
import json

from .merkle import build_merkle_tree, leaf_hash, compute_root_from_proof
from .signatures import verify_detached_signature


HEADERS = {'event_id', 'event_type', 'case_id', 'seq', 'prev_hash', 'payload'}


def verify_event_signatures(events, registry):
    errors = []
    for event in events:
        try:
            signed = event.signed
            if not isinstance(signed, dict):
                raise ValueError('missing signature')
            key_id = signed.get('signer_key_id', signed.get('key_id'))
            if 'signer_key_id' in signed and 'key_id' in signed and signed['key_id'] != key_id:
                raise ValueError('conflicting signer identifiers')
            if signed.get('algorithm', 'Ed25519') != 'Ed25519':
                raise ValueError('unsupported signature algorithm')
            if 'signed_headers' in signed and (len(signed['signed_headers']) != len(HEADERS) or set(signed['signed_headers']) != HEADERS):
                raise ValueError('signature must cover all event fields')
            obj = json.loads(event.canonical_bytes)
            obj.pop('signed', None)
            key = registry.get_key(key_id) if registry else None
            if key is None:
                raise ValueError('signing key missing from the bundle')
            # The question is whether this key was trustworthy when it signed, not
            # whether it may sign now. A rotated or expired key keeps its history;
            # a revoked key keeps only what it signed before the revocation.
            signed_at = obj.get('timestamp') or (obj.get('payload') or {}).get('timestamp')
            trustworthy, why = key.valid_at(signed_at)
            if not trustworthy:
                raise ValueError(f'signing key was not trustworthy for this event: {why}')
            message = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
            if not verify_detached_signature(key.public_key_hex, message, signed['signature']):
                raise ValueError('invalid Ed25519 signature')
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            errors.append(f'Event {event.event_id}: {exc}')
    return errors


def verify_batch_binding(events, manifest, bundle_path):
    errors = []
    ids = [e.event_id for e in events]
    if ids != manifest.event_ids or len(set(ids)) != len(ids):
        errors.append('Manifest event IDs do not exactly match loaded events')
    if any(e.case_id != manifest.case_id for e in events):
        errors.append('Event case ID does not match signed manifest')
    if (events[0].seq, events[-1].seq) != (manifest.start_seq, manifest.end_seq):
        errors.append('Manifest sequence bounds do not match loaded events')
    leaves = [leaf_hash(e.canonical_bytes) for e in events]
    if build_merkle_tree(leaves).hex() != manifest.root:
        errors.append('Loaded events do not match signed Merkle root')
    try:
        case = json.loads((bundle_path / 'case_manifest.json').read_text())
        if case['case_id'] != manifest.case_id or case['event_count'] != len(events):
            raise ValueError('case metadata does not match signed batch')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f'Case manifest: {exc}')
    try:
        proof = json.loads((bundle_path / 'merkle_proof.json').read_text())
        i = proof['leaf_index']
        if type(i) is not int or not 0 <= i < len(events) or type(proof['tree_size']) is not int or proof['tree_size'] != len(events):
            raise ValueError('invalid proof index or tree size')
        siblings = [bytes.fromhex(h) for h in proof['proof_hashes']]
        if len(siblings) != (len(events) - 1).bit_length() or any(len(h) != 32 for h in siblings):
            raise ValueError('invalid proof length')
        if proof['leaf_hash'] != leaves[i].hex() or proof['root'] != manifest.root:
            raise ValueError('proof is not bound to event and signed root')
        if compute_root_from_proof(leaves[i], siblings, i).hex() != manifest.root:
            raise ValueError('invalid inclusion proof')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f'Merkle proof: {exc}')
    return errors
