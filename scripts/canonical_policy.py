#!/usr/bin/env python3
"""Write the operator trust policy for a canonical fixture.

The canonical packages carry a fixture TSA. Trusting its CA is an operator
decision, so it lives in a policy the way it would in a real deployment, not
inside the package. This keeps the release gate offline: the policy and the CA are
both in the tree, so nothing depends on a public TSA being reachable.

Usage:
    scripts/canonical_policy.py <fixture-name> <output.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"
TSA_URL = "https://tsa.fixture.invalid/tsr"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    name, out = sys.argv[1], Path(sys.argv[2])
    package = FIXTURES / name
    if not package.is_dir():
        print(f"missing fixture package: {package}", file=sys.stderr)
        return 2

    policy = {
        "level": "standard",
        "provider_keys": json.loads((package / "providers.json").read_text()),
        "allowed_tsa_urls": [TSA_URL],
    }
    if (package / "ca.pem").exists():
        policy["trusted_roots"] = [str(package / "ca.pem")]
    if (package / "tsa.pem").exists():
        policy["untrusted_certificates"] = [str(package / "tsa.pem")]

    out.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
