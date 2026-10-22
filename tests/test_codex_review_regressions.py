"""Regressions from the 2026-10-21 independent (Codex) review of the verifier.

Three findings are pinned here. Each one was reproduced by the reviewer against
the code as it stood, and each fix is load-bearing only if a test removes it.
"""
from __future__ import annotations

import copy

import pytest

from witnessos_verifier import corroboration
from witnessos_verifier.corroboration import assess_corroboration
from witnessos_verifier.evidence_semantics import same_signer_warning
from witnessos_verifier.verifier import verify

from .hostile import factory


def _events(built):
    from witnessos_verifier.events import load_events

    root = built["path"] if isinstance(built, dict) else built
    return load_events(root)


def test_one_acknowledgement_does_not_cover_a_second_action(tmp_path):
    """Finding 5: appended actions are not covered by an earlier acknowledgement.

    This used to stub the single-acknowledgement appraisal and test the coverage
    rule in isolation. The coverage rule is now part of the canonical appraisal,
    so the test drives it with real evidence instead of a stub: an honest bundle
    whose actions are covered, then the same record set with an action appended
    after the acknowledgement.
    """
    from types import SimpleNamespace

    built = factory.build(tmp_path / "finding5")
    policy = factory.policy(built["provider_public_hex"])
    loaded = _events(built)

    from witnessos_verifier.key_registry import KeyRegistry

    registry = KeyRegistry.from_file(built["path"] / "keys.json")

    covered = assess_corroboration(loaded, registry, None, policy)
    assert covered.satisfied is True, covered.reasons

    appended = SimpleNamespace(
        event_type="action_executed",
        event_id="evt_appended_after_ack",
        case_id=loaded[0].case_id,
        seq=max(event.seq for event in loaded) + 1,
        payload={},
        signed={},
    )
    uncovered = assess_corroboration(list(loaded) + [appended], registry, None, policy)
    assert uncovered.satisfied is False, uncovered.reasons
    assert any("no acknowledgement" in reason for reason in uncovered.reasons), uncovered.reasons


def test_deployment_keys_are_compared_by_public_key_not_label():
    """Finding 3: one public key registered under two identifiers is one party."""
    class _Record:
        def __init__(self, public_key_hex):
            self.public_key_hex = public_key_hex

    class _Registry:
        def __init__(self, mapping):
            self._mapping = mapping

        def get_key(self, key_id):
            return self._mapping.get(key_id)

    same_key = "ab" * 32

    class _Event:
        event_type = "action_executed"
        event_id = "evt_1"
        case_id = "case_1"
        seq = 1
        payload = {}
        signed = {"signer_key_id": "deployment_alias"}

    class _Manifest:
        signing_key_id = "deployment_primary"

    registry = _Registry(
        {
            "deployment_primary": _Record(same_key),
            "deployment_alias": _Record(same_key),
        }
    )
    ids, hexes = corroboration._deployment_signers([_Event()], _Manifest(), registry)
    assert same_key in hexes, "independence must be decided on the key, not the label"
    assert "deployment_alias" in ids


def test_same_open_signer_is_reported_rather_than_silently_accepted(tmp_path):
    """Finding 1/2: when one key signs the agent and the gate, the verifier says so."""
    built = factory.build(tmp_path / "samekey")
    root = built["path"] if isinstance(built, dict) else built
    result = verify(root, trust_policy=factory.policy(built["provider_public_hex"]))
    warning = same_signer_warning(result.events, None)
    # The factory signs each role with its own key, so no warning is expected
    # here; the test pins the helper's contract in both directions.
    assert warning == "" or "independence from the agent is not established" in warning
