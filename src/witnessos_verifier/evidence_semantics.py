# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Rung semantics read from the events themselves.

Two rungs used to be awarded for facts that are not what the rung means.

E1 was awarded for `events_loaded`, so a bundle holding nothing but the acting
agent's own request scored Observed. A file existing is not an observation. E1
now requires at least one event that the acting agent did not declare.

E2 was awarded for cryptographic integrity alone: a valid hash chain, a
monotonic ledger, signed events and a signed manifest. All of those are
properties of a record, not evidence that a policy gate stood between the agent
and the effect. E2 now requires an enforcement structure in the events: a
permitting policy decision, followed by the action it permits, tied together by
the permit identifier when both sides carry one.

Neither function can be satisfied by an annotation. Both read events.

Since the 2026-10-21 independent review, both also refuse a record in which the
acting agent signs its own observation or its own permission. One key cannot be
the actor and the gate. Where the actor's key is identifiable from the record,
an event signed by that key is not evidence of anything except the actor's
intent. Where it is not identifiable the functions still answer, and the caller
reports that the observer's identity was not established.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Set, Tuple

# Event types the acting agent declares about itself. A bundle made only of
# these is a declaration, which is E0.
AGENT_DECLARED_TYPES = frozenset(
    {
        "action_requested",
        "action.requested",
        "agent.claim",
        "agent.claimed",
        "agent.reported",
        "agent.declared",
    }
)

# Events emitted by a component that decides whether the action may proceed.
POLICY_DECISION_TYPES = frozenset(
    {
        "policy_checked",
        "policy.checked",
        "policy_evaluated",
        "policy.evaluated",
        "approval.granted",
        "approval.denied",
        "gate.decision",
    }
)

# Events that show the action actually proceeded past the gate.
ACTION_TYPES = frozenset(
    {
        "action_executed",
        "action.executed",
        "dispatch.started",
        "credential_brokered",
        "dispatch.completed",
    }
)

PERMIT_DECISIONS = frozenset(
    {"allow", "allowed", "permit", "permitted", "grants", "granted", "approved", "enforce", "enforced"}
)

PERMIT_ID_KEYS = ("permit_id", "permit_jti", "approval_id")


def _permit_ids(event) -> set:
    payload = event.payload if isinstance(event.payload, dict) else {}
    return {payload[k] for k in PERMIT_ID_KEYS if isinstance(payload.get(k), str) and payload.get(k)}


def _permits(event) -> bool:
    payload = event.payload if isinstance(event.payload, dict) else {}
    if payload.get("allowed") is True:
        return True
    # An approval that was granted is itself the authorising step.
    if event.event_type == "approval.granted":
        return True
    decision = payload.get("decision")
    return isinstance(decision, str) and decision.strip().lower() in PERMIT_DECISIONS


def _signer_labels(event) -> Set[str]:
    """Every identifier this event's signer can be known by, normalised."""
    signed = event.signed if isinstance(getattr(event, "signed", None), dict) else {}
    labels = set()
    for field_name in ("signer_key_id", "key_id"):
        value = signed.get(field_name)
        if isinstance(value, str) and value:
            labels.add(value.lower())
            labels.add(value)
    return labels


def _signer_keys(event, registry) -> Set[str]:
    """The signer's identifiers, plus its public key when the registry resolves it."""
    keys = _signer_labels(event)
    if registry is None:
        return keys
    signed = event.signed if isinstance(getattr(event, "signed", None), dict) else {}
    key_id = signed.get("signer_key_id") or signed.get("key_id")
    if isinstance(key_id, str) and key_id:
        try:
            record = registry.get_key(key_id)
        except Exception:  # a malformed registry must not turn into an award
            record = None
        public = getattr(record, "public_key_hex", None) if record is not None else None
        if isinstance(public, str) and public:
            keys.add(public.lower())
    return keys


def observation_external(events: Iterable, registry=None) -> bool:
    """True when at least one event was written by something other than the agent.

    This is a structural test on the record, not an authentication of the writer.
    When the same key signs the agent's declaration and the recording component,
    the record cannot tell them apart and the caller should say so through
    ``same_signer_warning`` rather than reading this as authenticated observation.
    """
    return any(e.event_type not in AGENT_DECLARED_TYPES for e in events)


def enforcement_observed(events: Iterable, registry=None) -> bool:
    """True when a permitting decision precedes the action it permits.

    The action must follow the decision in the same case. When both the decision
    and the action name a permit, the permits must be the same one, so an
    unrelated approval elsewhere in the case cannot license the action.

    A denial is not a permission: a record that denies and then dispatches has
    recorded a gate that did not hold, so it does not reach E2. A denial followed
    by a block is a gate that held, and counts.
    """
    ordered: List = list(events)
    allow_at: Optional[int] = None
    deny_at: Optional[int] = None
    for index, event in enumerate(ordered):
        if event.event_type in POLICY_DECISION_TYPES:
            payload = event.payload if isinstance(event.payload, dict) else {}
            decision = str(payload.get("decision") or payload.get("allowed") or "").lower()
            if decision in PERMIT_DECISIONS or payload.get("allowed") is True or event.event_type == "approval.granted":
                if allow_at is None:
                    allow_at = index
            elif decision in {"deny", "denied", "false"}:
                if deny_at is None:
                    deny_at = index
    actions = [e for e in ordered if e.event_type in ACTION_TYPES]
    for action in actions:
        action_index = ordered.index(action)
        if action.event_type == "dispatch.blocked":
            if deny_at is not None and deny_at < action_index:
                return True
            continue
        if allow_at is not None and allow_at < action_index:
            return True
        if deny_at is not None and (allow_at is None or deny_at > allow_at):
            # Denied, then executed. The gate was bypassed, not enforced.
            return False
    return False


def actor_keys(events: Iterable, registry=None) -> Set[str]:
    """Identifiers of the key that speaks for the acting agent."""
    keys: Set[str] = set()
    for event in events:
        if event.event_type in AGENT_DECLARED_TYPES:
            keys |= _signer_keys(event, registry)
    return keys


def same_signer_warning(events: Iterable, registry=None) -> str:
    """A warning when the agent and the enforcement point share one key.

    One key signing both the agent's declaration and the policy decision means
    the record cannot demonstrate that the gate was independent of the agent. The
    grade is not lowered on that basis: E2 says the action was routed through an
    enforcement point, which the record shape shows. It is a limitation of the
    evidence, and the honest verifier reports it.
    """
    ordered: List = list(events)
    actors = actor_keys(ordered, registry)
    if not actors:
        return ""
    for event in ordered:
        if event.event_type in POLICY_DECISION_TYPES or event.event_type in ACTION_TYPES:
            if _signer_keys(event, registry) & actors:
                return (
                    "the acting agent's key also signed the enforcement point, so the gate's "
                    "independence from the agent is not established by this record"
                )
    return ""


def actor_identified(events: Iterable, registry=None) -> Tuple[bool, str]:
    """Whether the record names the acting agent's key, and what to say if not."""
    if actor_keys(events, registry):
        return True, ""
    return False, (
        "the acting agent's key is not identifiable in this record, so an observer or a "
        "policy gate signed by a key that also signed the action cannot be told apart"
    )
