# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WitnessOS Verifier — Standalone library for verifying WitnessOS evidence bundles.

This package contains NO gateway, credential broker, connector, policy engine,
or key management code. It is a pure verification client.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

# Single source of truth: the version declared in pyproject.toml, read back from
# the installed distribution metadata. Do not hardcode a version here. A
# duplicate literal cannot be bumped by the release process, so the two drift and
# the shipped artefact lies about which version produced a result, which defeats
# the provenance question this project exists to answer.
#
# Defect found 2026-10-04 by building the wheel and running it from a clean
# virtualenv: pyproject.toml declared 0.3.0, the wheel metadata said 0.3.0 and
# ``witnessos-verifier --version`` said 0.2.0. Guarded by tests/test_version.py.
try:
    __version__ = _distribution_version("witnessos-verifier")
except PackageNotFoundError:  # pragma: no cover - a source tree with no install
    __version__ = "0.0.0+unknown"
__all__ = ["verifier", "events", "signatures", "key_registry", "case_chain",
           "ledger", "merkle", "manifest", "timestamp", "worm", "grades", "der"]
