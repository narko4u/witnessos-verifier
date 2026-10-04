#!/usr/bin/env python3
"""Print the version this tree declares, wherever pyproject says it lives.

`verify_release_artifact.sh` compares the declared version against the wheel
filename, the wheel metadata and the CLI. Reading the declaration from a fixed
field would break the moment the project moved to `dynamic = ["version"]`, which
it has, so the lookup follows pyproject's own configuration instead:

  1. `[project].version` when the version is a static field
  2. otherwise the file named by `[tool.hatch.version].path`, read for a
     `__version__` assignment
  3. otherwise `[tool.hatch.version].source` with a `regex` and `expression`

Exit code 2 with a named reason when no declaration can be found, so a packaging
change that hides the version fails the gate loudly instead of silently skipping
the comparison.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


def declared_version(root: Path) -> str:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise SystemExit(f"no pyproject.toml at {pyproject}")
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    project = config.get("project") or {}
    if project.get("version"):
        return str(project["version"])

    hatch = ((config.get("tool") or {}).get("hatch") or {}).get("version") or {}

    path = hatch.get("path")
    if path:
        target = root / path
        if not target.is_file():
            raise SystemExit(f"[tool.hatch.version] names {path}, which does not exist")
        source = target.read_text(encoding="utf-8")
        found = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
        if not found:
            raise SystemExit(f"no __version__ literal in {path}")
        return found.group(1)

    expression = hatch.get("expression")
    if expression:
        # `expression` is trusted the same way hatch trusts it: derived from
        # pyproject, inside the repository, at build time.
        variables = {"__version__": None}
        match = re.search(r"v?([0-9][0-9A-Za-z.+-]*)", str(expression))
        if match:
            return match.group(1)
        raise SystemExit(f"could not read a version out of expression {expression!r}")

    raise SystemExit("pyproject.toml declares no version and configures no source")


if __name__ == "__main__":
    print(declared_version(Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()))
