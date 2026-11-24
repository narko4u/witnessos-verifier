"""Exit status must answer the question an automated caller actually asks.

The README promises exit 1 when supplied evidence "fails or cannot be verified",
and the fixture table says `canonical-e2` is "E2, exit 1". Measured on v1.2.0 the
two unprovisioned-operator-input cases disagree with each other:

    canonical-e2, no trusted CA            -> grade E2, exit 1
    canonical-e4, provider key stripped    -> grade E2, exit 0

Both are the same situation: the record is sound, the operator did not provision
an input the ladder needs. A caller scripting against the exit code cannot tell
those apart, and a record that never reached the level the caller requires is
reported as success.

These tests pin the intended contract:

* by default, any unmet requirement is exit 1 (fail-closed);
* `--report-only` keeps the exit code tied to bundle validity alone;
* `--require-grade` lets a caller demand a floor, and exit 1 below it;
* a requirement the ladder satisfied is listed, so the printed ladder has no
  missing rung.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

from witnessos_verifier.cli import main

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "fixtures"
TSA = "https://tsa.fixture.invalid/tsr"


def _policy(name: str, out_dir: Path, *, strip_provider_keys: bool = False) -> Path:
    """Build the operator policy the way a relying party would hold it."""
    out = out_dir / f"{name}.json"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "canonical_policy.py"), name, str(out)],
        check=True,
        capture_output=True,
    )
    if strip_provider_keys:
        policy = json.loads(out.read_text())
        policy["provider_keys"] = {}
        out.write_text(json.dumps(policy))
    return out


def _run(name: str, tmp_path: Path, *extra: str, strip_provider_keys: bool = False):
    policy = _policy(name, tmp_path, strip_provider_keys=strip_provider_keys)
    args = ["verify", str(FIXTURES / name / "bundle"), "--trust-policy", str(policy), "--tsa-url", TSA, *extra]
    return CliRunner().invoke(main, args)


def test_an_unmet_requirement_exits_one_by_default(tmp_path):
    """A record that does not reach the rung its own ladder needs is not success."""
    result = _run("canonical-e4", tmp_path, strip_provider_keys=True)
    assert result.exit_code == 1, result.output
    assert "Grade:  E2" in result.output


def test_report_only_keeps_a_sound_bundle_at_zero(tmp_path):
    """The old tolerance stays reachable, by asking for it explicitly."""
    result = _run("canonical-e4", tmp_path, "--report-only", strip_provider_keys=True)
    assert result.exit_code == 0, result.output


def test_require_grade_below_the_derived_grade_exits_zero(tmp_path):
    result = _run("canonical-e4", tmp_path, "--require-grade", "E2", strip_provider_keys=True)
    assert result.exit_code == 0, result.output


def test_require_grade_above_the_derived_grade_exits_one(tmp_path):
    result = _run("canonical-e4", tmp_path, "--require-grade", "E4", strip_provider_keys=True)
    assert result.exit_code == 1, result.output


def test_a_fully_met_record_exits_zero_on_every_path(tmp_path):
    for extra in ([], ["--require-grade", "E4"], ["--report-only"]):
        result = _run("canonical-e4", tmp_path, *extra)
        assert result.exit_code == 0, (extra, result.output)
        assert "Grade:  E4" in result.output


def test_the_printed_ladder_has_no_skipped_rung(tmp_path):
    """E4 rests on E3, so a satisfied corroboration must be shown, not implied."""
    result = _run("canonical-e4", tmp_path)
    met = [line for line in result.output.splitlines() if line.strip().startswith("✓ E3")]
    assert met, "E3 was satisfied but is absent from the requirement list"
