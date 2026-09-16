# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WitnessOS Verifier — Standalone library for verifying WitnessOS evidence bundles.

This package contains NO gateway, credential broker, connector, policy engine,
or key management code. It is a pure verification client.
"""

__version__ = "0.3.4"
__all__ = ["verifier", "events", "signatures", "key_registry", "case_chain",
           "ledger", "merkle", "manifest", "timestamp", "worm", "grades", "der"]
