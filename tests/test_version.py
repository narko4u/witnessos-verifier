"""The version a user reads must be the version they installed.

Regression guard. Found 2026-10-04 by building the artefact and running it from a
clean virtualenv: the 0.3.0 wheel self-reported 0.2.0, because ``__init__.py``
hardcoded ``__version__`` while ``pyproject.toml`` is the real single source of
truth. An installed artefact that misstates its own version defeats the very
provenance question this project exists to answer, so it cannot be left to
review.

``pyproject.toml`` holds the version. The package reads it back from the
installed distribution metadata, so the two cannot drift again.
"""

import importlib.metadata

import pytest
from click.testing import CliRunner

from witnessos_verifier import __version__
from witnessos_verifier.cli import main

DIST_NAME = "witnessos-verifier"


def _installed_version() -> str:
    return importlib.metadata.version(DIST_NAME)


def test_package_version_matches_distribution_metadata() -> None:
    assert __version__ == _installed_version()


def test_package_version_is_not_unknown_in_an_installed_tree() -> None:
    # A local placeholder is acceptable only when no distribution is installed.
    # Here one is, so a placeholder means the metadata lookup silently failed.
    assert __version__ != "0.0.0+unknown"


def test_cli_version_option_reports_the_installed_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0, result.output
    assert _installed_version() in result.output


def test_version_is_read_not_hardcoded() -> None:
    """The module must not assign a literal version of its own.

    A hardcoded duplicate is the defect: the release process bumps
    ``pyproject.toml`` and cannot reach it, so the two drift and the shipped
    artefact lies about which version produced a result. Guard the mechanism
    rather than a particular value.
    """
    import re
    from pathlib import Path

    import witnessos_verifier

    source = Path(witnessos_verifier.__file__).read_text(encoding="utf-8")
    literals = re.findall(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
    allowed = {"0.0.0+unknown"}
    offenders = [lit for lit in literals if lit not in allowed]
    assert not offenders, (
        f"__init__.py assigns a hardcoded version {offenders}; read it from the "
        "installed distribution metadata instead"
    )
    assert "importlib.metadata" in source, (
        "__version__ must be read from the installed distribution metadata"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
