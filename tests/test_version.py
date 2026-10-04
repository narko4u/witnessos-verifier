"""The version a user reads must be the version they installed.

Regression guard. Found by building the artefact and running it from a clean
virtualenv: shipped wheels self-reported a version older than their own filename,
because one literal named the distribution while another was printed.

The fix is single-sourcing. `pyproject.toml` declares no version of its own and
`[tool.hatch.version]` reads the one assignment in
`src/witnessos_verifier/__init__.py`, so the distribution filename, the wheel
metadata and `witnessos-verifier --version` all derive from that single line.

These tests guard the property rather than a mechanism. The original drift
survived a release workflow that did assert something about the version, because
it asserted against a value read from a third place. So the checks here are:
there is exactly one version literal anywhere in the package, pyproject does not
carry a second one, and what is installed agrees with it.
"""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

import witnessos_verifier
import witnessos_verifier.cli

DIST_NAME = "witnessos-verifier"
REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(witnessos_verifier.__file__).resolve().parent


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_declares_no_version_of_its_own():
    """A second declaration is the defect. Guard the absence, not a value."""
    project = _pyproject().get("project", {})
    assert "version" not in project, (
        "pyproject.toml declares its own version; "
        "[tool.hatch.version] is the single source, so a static field here is a second copy"
    )
    assert "version" in (project.get("dynamic") or []), (
        "the version is not listed as dynamic, so nothing is single-sourced"
    )


def test_the_version_source_is_the_module_that_defines_the_version():
    """Whatever pyproject points at must be the file the package actually imports."""
    hatch = ((_pyproject().get("tool") or {}).get("hatch") or {}).get("version") or {}
    declared_path = hatch.get("path")
    assert declared_path, "no [tool.hatch.version] path is configured"
    source_file = (REPO_ROOT / str(declared_path)).resolve()
    assert source_file == (PACKAGE_DIR / "__init__.py").resolve(), (
        f"the version is read from {declared_path}, which is not the module the package "
        "imports, so the two can disagree"
    )


def test_there_is_exactly_one_version_literal_in_the_package():
    pattern = re.compile(r'__version__\s*=\s*["\']([^"\']+)["\']')
    found: list[tuple[str, str]] = []
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        for value in pattern.findall(path.read_text(encoding="utf-8")):
            found.append((path.name, value))
    assert len(found) == 1, f"expected exactly one version literal, found {found}"
    assert found[0][1] == witnessos_verifier.__version__


def test_the_installed_distribution_agrees_with_the_source():
    try:
        installed = importlib.metadata.version(DIST_NAME)
    except importlib.metadata.PackageNotFoundError:      # pragma: no cover
        pytest.skip("no distribution installed in this environment")
        return
    assert witnessos_verifier.__version__ == installed


def test_the_wheel_name_would_carry_the_same_version():
    """The filename is derived from the metadata, so assert the shape is coherent."""
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", witnessos_verifier.__version__), (
        f"{witnessos_verifier.__version__!r} is not a release version"
    )


def test_cli_version_option_reports_the_source_version():
    result = CliRunner().invoke(witnessos_verifier.cli.main, ["--version"])
    assert result.exit_code == 0, result.output
    assert witnessos_verifier.__version__ in result.output


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
