# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Key registry for WitnessOS verification.

Manages public keys used for signature verification.
Keys are loaded from the evidence bundle's keys.json file.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .signatures import KeyStatus


class KeyRegistryError(Exception):
    """Key registry error."""


def _parse_time(value: str):
    """Parse an ISO 8601 instant, treating a naive value as UTC.

    Compared as instants, not as strings: an offset of +10:00 makes a lexical
    comparison wrong by ten hours, which is the difference between "before the
    revocation" and "after it" for anyone in Brisbane.
    """
    from datetime import datetime, timezone

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _later(a: str, b: str) -> bool:
    try:
        return _parse_time(a) > _parse_time(b)
    except (TypeError, ValueError):
        return True  # an instant we cannot read cannot prove the signature came first


@dataclass
class KeyRecord:
    key_id: str
    public_key_hex: str
    status: str
    algorithm: str = "Ed25519"
    created_at: Optional[str] = None
    revoked_at: Optional[str] = None
    description: Optional[str] = None
    retired_at: Optional[str] = None
    expires_at: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.status in KeyStatus.valid_statuses()

    def valid_at(self, when: Optional[str]) -> tuple[bool, str]:
        """Was this key's signature trustworthy at the moment it was made?

        `is_valid` answers the operator's question, "may this key sign now".
        A relying party holding a two-year-old receipt is asking a different one.
        Collapsing the two has exactly two outcomes and both are wrong: fail every
        receipt the key ever signed, or trust a revoked key for the rest of its
        life. So the retired and revoked cases are resolved against `when`, the
        time the signature was made.

        A record with no revocation instant and no status we recognise fails
        closed. An unknown state is not a licence.
        """
        status = (self.status or "").lower()

        if status == KeyStatus.ACTIVE:
            return True, "active"
        if status == "retired":
            if self.retired_at and when and _later(when, self.retired_at):
                return False, f"key was retired at {self.retired_at}, before this signature"
            return True, "retired after this signature was made"
        if status == KeyStatus.REVOKED or status == "retired_bad":
            if not self.revoked_at:
                return False, "key is revoked and carries no revocation instant"
            if not when:
                return False, f"key was revoked at {self.revoked_at} and the signature carries no time"
            if _later(when, self.revoked_at):
                return False, f"key was revoked at {self.revoked_at}, before this signature"
            return True, f"signed before the key was revoked at {self.revoked_at}"
        if status == KeyStatus.EXPIRED:
            if self.expires_at and when and _later(when, self.expires_at):
                return False, f"key expired at {self.expires_at}, before this signature"
            return True, "signed inside the key's validity window"
        return False, f"unrecognised key status {self.status!r}"

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)


class KeyRegistry:
    """A registry of public keys loaded from a bundle."""

    def __init__(self):
        self._keys: Dict[str, KeyRecord] = {}

    def add_key(self, key: KeyRecord) -> None:
        self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def from_file(cls, path: Path) -> "KeyRegistry":
        """Load keys from a keys.json file."""
        if not path.exists():
            raise KeyRegistryError(f"Keys file not found: {path}")

        data = json.loads(path.read_text())
        registry = cls()

        keys = data if isinstance(data, list) else data.get("keys", [])
        for k in keys:
            record = KeyRecord(
                key_id=k["key_id"],
                public_key_hex=k["public_key_hex"],
                status=k.get("status", KeyStatus.ACTIVE),
                algorithm=k.get("algorithm", "Ed25519"),
                created_at=k.get("created_at"),
                revoked_at=k.get("revoked_at"),
                description=k.get("description"),
                retired_at=k.get("retired_at"),
                expires_at=k.get("expires_at"),
            )
            registry.add_key(record)

        if not registry._keys:
            raise KeyRegistryError("No keys found in keys file")

        return registry

    @classmethod
    def from_dict(cls, data: list) -> "KeyRegistry":
        """Create a KeyRegistry from a list of key dicts (for testing)."""
        registry = cls()
        for k in data:
            record = KeyRecord(
                key_id=k["key_id"],
                public_key_hex=k["public_key_hex"],
                status=k.get("status", KeyStatus.ACTIVE),
                algorithm=k.get("algorithm", "Ed25519"),
                created_at=k.get("created_at"),
                revoked_at=k.get("revoked_at"),
                description=k.get("description"),
                retired_at=k.get("retired_at"),
                expires_at=k.get("expires_at"),
            )
            registry.add_key(record)
        return registry
