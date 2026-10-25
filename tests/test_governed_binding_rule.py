# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0

"""The versioned governed-action binding, as a relying party computes it.

v1 bound the intent, steps, capability profile and robot class. It did not bind
which mission the case authorised, so the same execution content could be
relabelled as a different mission and still grade. v2 adds the external action
identity and is versioned so that v1 evidence keeps verifying under v1 semantics.

These tests fix the published rule: the field set, the serializer, the encoding,
the hash and the prefix. A second implementation elsewhere in the estate has to
agree with this one byte for byte, which is why the rule is stated here rather
than imported from the engine.
"""

from __future__ import annotations

import hashlib

from witnessos_verifier.governed_binding import (
    BINDING_VERSION,
    FIELDS,
    check,
    declares_v2,
    digest,
)

CASE = "wos_0123456789ab"
EXTERNAL = "aa3d4dc5447b7c6d"
ACTION = "sha256:" + "85a2143a" + "0" * 56


def test_the_rule_is_published_and_versioned():
    assert BINDING_VERSION == "governed-action-binding/v2"
    assert FIELDS == (
        "binding_version",
        "case_id",
        "external_action_id",
        "action_digest",
        "action_type",
        "target",
    )


def test_the_digest_is_the_published_canonical_form():
    expected_body = (
        b'{"action_digest":"' + ACTION.encode() + b'",'
        b'"action_type":"robot.mission.execute",'
        b'"binding_version":"governed-action-binding/v2",'
        b'"case_id":"' + CASE.encode() + b'",'
        b'"external_action_id":"' + EXTERNAL.encode() + b'",'
        b'"target":"robot"}'
    )
    expected = "sha256:" + hashlib.sha256(expected_body).hexdigest()
    assert digest(
        case_id=CASE,
        external_action_id=EXTERNAL,
        action_digest=ACTION,
        action_type="robot.mission.execute",
        target="robot",
    ) == expected


def test_the_same_content_under_a_different_mission_is_a_different_binding():
    one = digest(
        case_id=CASE,
        external_action_id=EXTERNAL,
        action_digest=ACTION,
        action_type="robot.mission.execute",
        target="robot",
    )
    other = digest(
        case_id=CASE,
        external_action_id="ffffffffffffffff",
        action_digest=ACTION,
        action_type="robot.mission.execute",
        target="robot",
    )
    assert one != other


def test_a_different_case_binding_the_same_action_is_a_different_digest():
    one = digest(case_id=CASE, external_action_id=EXTERNAL, action_digest=ACTION,
                 action_type="robot.mission.execute", target="robot")
    other = digest(case_id="wos_ba9876543210", external_action_id=EXTERNAL,
                   action_digest=ACTION, action_type="robot.mission.execute", target="robot")
    assert one != other


def test_v2_is_declared_by_the_version_not_by_a_guess():
    assert declares_v2(BINDING_VERSION)
    assert declares_v2("governed-action-binding/v3")
    assert not declares_v2("")
    assert not declares_v2(None)
    assert not declares_v2("governed-action-binding/v1")


BINDING = digest(
    case_id=CASE,
    external_action_id=EXTERNAL,
    action_digest=ACTION,
    action_type="robot.mission.execute",
    target="robot",
)


def _check(**overrides):
    base = {
        "case_id": CASE,
        "declared_version": BINDING_VERSION,
        "stored_binding": BINDING,
        "attested_binding": BINDING,
        "case_external_action_id": EXTERNAL,
        "effect_external_action_id": EXTERNAL,
        "attested_external_action_id": EXTERNAL,
        "action_digest": ACTION,
        "action_type": "robot.mission.execute",
        "target": "robot",
        "required": True,
    }
    base.update(overrides)
    return check(**base)


def test_agreement_passes():
    ok, reasons, facts = _check()
    assert ok, reasons
    assert facts["binding_external_action_id"] == EXTERNAL
    assert facts["binding_recomputed"] == BINDING


def test_an_effect_naming_another_action_is_refused():
    ok, reasons, _ = _check(effect_external_action_id="ffffffffffffffff")
    assert not ok
    assert any("the effect names external action" in r for r in reasons)


def test_an_attestation_naming_another_action_is_refused():
    ok, reasons, _ = _check(attested_external_action_id="ffffffffffffffff")
    assert not ok
    assert any("the attestation names external action" in r for r in reasons)


def test_a_case_without_an_external_action_cannot_satisfy_v2():
    ok, reasons, _ = _check(case_external_action_id="")
    assert not ok
    assert any("records no external action identity" in r for r in reasons)


def test_evidence_declaring_no_version_fails_closed():
    ok, reasons, _ = _check(declared_version="")
    assert not ok
    assert any("declares no binding version" in r for r in reasons)


def test_a_stored_binding_that_does_not_recompute_is_refused():
    ok, reasons, _ = _check(stored_binding="sha256:" + "1" * 64)
    assert not ok
    assert any("does not recompute from its own fields" in r for r in reasons)


def test_an_attestation_binding_a_different_action_is_refused():
    ok, reasons, _ = _check(attested_binding="sha256:" + "1" * 64)
    assert not ok
    assert any("binds a different governed action" in r for r in reasons)


def test_a_case_that_records_no_binding_digest_cannot_satisfy_v2():
    ok, reasons, _ = _check(stored_binding="")
    assert not ok
    assert any("records no v2 binding digest" in r for r in reasons)
