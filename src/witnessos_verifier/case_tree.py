"""The V1 canonical event encodings.

Two encodings, each with exactly one definition and one purpose:

  signature bytes  the six headers, sorted keys, compact separators. This is
                   what an event's signature covers, and what the record's own
                   `signed_headers` states it covers. The signature block is
                   never inside the bytes it signs.

  commitment bytes the same six headers plus the signature block when present.
                   This is what the prior-events Merkle root hashes, matching
                   the engine's `build_case_tree` leaf rule, so one history has
                   one root across both implementations.

Neither is a guess: a commitment that matches under some other serialisation is
a commitment to different events.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

from .merkle import build_merkle_tree, leaf_hash

HEADERS = ("case_id", "event_id", "event_type", "payload", "prev_hash", "seq")


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signature_bytes(envelope: Mapping) -> bytes:
    """The bytes an event's signature covers: the six headers, nothing else."""
    return canonical_bytes({key: envelope.get(key) for key in HEADERS})


def commitment_bytes(envelope: Mapping) -> bytes:
    """The bytes the prior-events root hashes: headers plus the signature block."""
    obj = {key: envelope.get(key) for key in HEADERS}
    if envelope.get("signed") is not None:
        obj["signed"] = envelope["signed"]
    return canonical_bytes(obj)


def envelope_hash(envelope: Mapping) -> str:
    return hashlib.sha256(commitment_bytes(envelope)).hexdigest()


def case_root(envelopes: Iterable[Mapping]) -> str:
    """The prior-events root: 64 lowercase hex, no prefix."""
    leaves = [leaf_hash(commitment_bytes(envelope)) for envelope in envelopes]
    if not leaves:
        raise ValueError("cannot build a tree over zero envelopes")
    return build_merkle_tree(leaves).hex()
