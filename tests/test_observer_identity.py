# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
"""E1 as an identity claim: the operator's observer binding decides.

E1 as a shape only needs an event written by something other than the acting
agent. E1 as an identity claim needs a trust decision made outside the bundle,
which is what `observer_keys` plus `require_observer_identity` express.
"""
from __future__ import annotations

from witnessos_verifier.grades import Grade, derive_grade


def grade(**overrides):
    args: dict[str, object] = dict(
        events_loaded=True,
        chain_result=None,
        ledger_result=None,
        manifest_result=None,
        corroboration=None,
        timestamp_result=None,
        worm_result=None,
        observation_external=True,
    )
    args.update(overrides)
    return derive_grade(**args)


def test_shape_only_reaches_e1():
    result = grade()
    assert result.grade is Grade.E1


def test_required_identity_without_binding_caps_at_e0():
    result = grade(require_observer_identity=True, observer_identity=None)
    assert result.grade is Grade.E0
    assert any("Observer identity not established" in m for m in result.requirements_missing)


def test_required_identity_with_binding_reaches_e1():
    result = grade(require_observer_identity=True, observer_identity="Sovereign sensor, Brisbane")
    assert result.grade is Grade.E1
    assert any("Observer identity established" in m for m in result.requirements_met)


def test_binding_is_recorded_even_when_not_required():
    result = grade(observer_identity="Sovereign sensor, Brisbane")
    assert result.grade is Grade.E1
    assert any("Observer identity established" in m for m in result.requirements_met)


def test_no_observation_stays_e0_even_with_binding():
    result = grade(observation_external=False, observer_identity="Sovereign sensor")
    assert result.grade is Grade.E0
