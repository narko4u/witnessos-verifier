#!/usr/bin/env bash
# Verify the artefact a user installs, not the working tree.
#
# The test suite imports src/, so a packaging fault is invisible to it. This gate
# builds the wheel, installs it into a throwaway virtualenv that cannot see the
# source tree, and then asserts the claims this project makes on its own behalf:
# that the artifact resolves cleanly, that its version is self-consistent end to
# end, and that the real CLI grades the shipped fixtures as documented.
#
# It runs as the release-artifact job in CI and again inside the Release workflow
# before anything is signed or published. A wheel that has never been executed is
# not a release.
#
# Usage:
#   scripts/verify_release_artifact.sh [--wheel PATH] [--keep-tmp] [--quiet]
#
#   --wheel PATH   verify an existing wheel instead of building one
#   --keep-tmp     leave the temporary tree in place for inspection
#   --quiet        only print failures and the final verdict
#
# Exit codes: 0 all assertions passed, 1 any assertion failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHEEL=""
KEEP_TMP=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --wheel) WHEEL="${2:-}"; shift 2 ;;
    --keep-tmp) KEEP_TMP=1; shift ;;
    --quiet|-q) QUIET=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/wosv-release-gate.XXXXXX")"
cleanup() {
  if [ "$KEEP_TMP" -eq 1 ]; then
    echo "temporary tree kept at $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

FAILURES=0

say()  { [ "$QUIET" -eq 1 ] || echo "$*"; }
step() { [ "$QUIET" -eq 1 ] || { echo; echo "== $*"; }; }
pass() { echo "   PASS  $*"; }
fail() {
  echo "   FAIL  $*" >&2
  FAILURES=$((FAILURES + 1))
}

# ---------------------------------------------------------------------------
# 1. Build the wheel, or take the one we were handed.
# ---------------------------------------------------------------------------
step "Build"
if [ -n "$WHEEL" ]; then
  [ -f "$WHEEL" ] || { echo "::error::--wheel path does not exist: $WHEEL" >&2; exit 1; }
  WHEEL="$(cd "$(dirname "$WHEEL")" && pwd)/$(basename "$WHEEL")"
  say "using supplied wheel: $WHEEL"
else
  python3 -m venv "$TMP/build-venv"
  "$TMP/build-venv/bin/pip" install --quiet --upgrade pip build
  "$TMP/build-venv/bin/python" -m build --wheel --outdir "$TMP/dist" "$REPO_ROOT" \
    > "$TMP/build.log" 2>&1 || { cat "$TMP/build.log" >&2; echo "::error::build failed" >&2; exit 1; }
  WHEEL="$(find "$TMP/dist" -name '*.whl' -print -quit)"
  [ -n "$WHEEL" ] || { echo "::error::build produced no wheel" >&2; exit 1; }
  say "built: $(basename "$WHEEL")"
fi

# ---------------------------------------------------------------------------
# 2. Install into a clean room that cannot see the source tree.
# ---------------------------------------------------------------------------
step "Clean-room install"
ROOM="$TMP/room"
python3 -m venv "$ROOM"
"$ROOM/bin/pip" install --quiet --upgrade pip
if ! "$ROOM/bin/pip" install --quiet "$WHEEL" > "$TMP/install.log" 2>&1; then
  cat "$TMP/install.log" >&2
  echo "::error::the wheel failed to install into a clean virtualenv" >&2
  exit 1
fi
say "installed cleanly"

# Anything run below executes from $TMP, so src/ cannot shadow the installed copy.
cd "$TMP"

step "Assertion 1: the package resolves inside the clean room"
RESOLVED="$("$ROOM/bin/python" -c 'import witnessos_verifier as m; print(m.__file__)')"
say "resolved to: $RESOLVED"
case "$RESOLVED" in
  "$ROOM"/*) pass "resolves inside the clean room" ;;
  *)         fail "resolves OUTSIDE the clean room: $RESOLVED" ;;
esac
case "$RESOLVED" in
  "$REPO_ROOT"/src/*) fail "the source tree shadowed the installed package" ;;
  *)                  pass "the source tree did not shadow the installed package" ;;
esac
if [ -n "$(find "$ROOM/lib" -name '__editable__*' -print -quit 2>/dev/null)" ]; then
  fail "editable-install marker present in the clean room"
else
  pass "no editable-install marker"
fi

step "Assertion 2: the three versions agree"
# The distribution filename carries the version in field 2, since the project
# name uses underscores rather than hyphens.
WHEEL_VERSION="$(basename "$WHEEL" | awk -F- '{print $2}')"
META_VERSION="$("$ROOM/bin/python" -c \
  'from importlib.metadata import version; print(version("witnessos-verifier"))')"
CLI_VERSION="$("$ROOM/bin/witnessos-verifier" --version | sed -nE 's/.*version[ ,]+//p' | tr -d '[:space:]')"
DECLARED_VERSION="$(python3 "$REPO_ROOT/scripts/declared_version.py" "$REPO_ROOT" 2>/dev/null)" || true

say "wheel filename : $WHEEL_VERSION"
say "wheel metadata : $META_VERSION"
say "cli --version  : $CLI_VERSION"
say "declared       : $DECLARED_VERSION"

[ "$WHEEL_VERSION" = "$META_VERSION" ] \
  && pass "filename matches metadata" \
  || fail "filename '$WHEEL_VERSION' does not match metadata '$META_VERSION'"

[ "$META_VERSION" = "$CLI_VERSION" ] \
  && pass "the installed CLI reports the version it was built as" \
  || fail "the CLI reports '$CLI_VERSION' but the wheel metadata says '$META_VERSION'"

[ "$META_VERSION" = "$DECLARED_VERSION" ] \
  && pass "matches pyproject.toml" \
  || fail "wheel metadata '$META_VERSION' does not match pyproject.toml '$DECLARED_VERSION'"

# ---------------------------------------------------------------------------
# 3. The real CLI grades the shipped fixtures as documented.
# ---------------------------------------------------------------------------
step "Assertion 3: the shipped fixtures grade as documented"

CERTS="$REPO_ROOT/tests/public_tsa_certificates"
POLICY_TWO_PARTY="$CERTS/two-party-standard.json"
POLICY_CUSTODY="$CERTS/two-party-requiring-custody.json"
TSA_URL="https://freetsa.org/tsr"

[ -f "$POLICY_TWO_PARTY" ] || fail "missing profile policy: $POLICY_TWO_PARTY"
[ -f "$POLICY_CUSTODY" ]   || fail "missing profile policy: $POLICY_CUSTODY"

check_case() {
  # check_case <fixture> <label> <expected-grade> <expected-exit> [policy] 
  local fixture="$1" label="$2" want_grade="$3" want_exit="$4" policy="${5:-}"
  local bundle="$REPO_ROOT/fixtures/$fixture"
  local args=("verify" "$bundle" "--json")
  if [ -n "$policy" ]; then
    args+=("--trust-policy" "$policy" "--tsa-url" "$TSA_URL")
  fi

  local out rc got_grade
  set +e
  out="$("$ROOM/bin/witnessos-verifier" "${args[@]}" 2>&1)"
  rc=$?
  set -e

  got_grade="$(printf '%s' "$out" | "$ROOM/bin/python" -c \
    'import json,sys
try:
    print(json.load(sys.stdin).get("grade",""))
except Exception:
    print("")' 2>/dev/null || true)"

  if [ -z "$got_grade" ]; then
    # Fall back to reading the grade off the human output rather than treat a
    # parser problem as a grading result.
    got_grade="$(printf '%s' "$out" | grep -oE 'E[0-4]' | head -1 || true)"
  fi

  local ok=1
  [ "$got_grade" = "$want_grade" ] || ok=0
  [ "$rc" = "$want_exit" ] || ok=0
  if [ "$ok" -eq 1 ]; then
    pass "$fixture / $label: grade $got_grade, exit $rc (as documented)"
  else
    fail "$fixture / $label: got grade '$got_grade', exit $rc; documented grade '$want_grade', exit $want_exit"
    [ "$QUIET" -eq 1 ] || printf '%s\n' "$out" | tail -20
  fi
}

for fixture in e4-gmail-approved-send e4-stripe-refund; do
  [ -d "$REPO_ROOT/fixtures/$fixture" ] || { fail "missing fixture: $fixture"; continue; }
  # WOS-E4-TWO-PARTY: E4 on the cryptography alone, no third party in the loop.
  check_case "$fixture" "WOS-E4-TWO-PARTY"          "E4" 0 "$POLICY_TWO_PARTY"
  # WOS-E4-TWO-PARTY-RETENTION: retention is demanded, no receipt is present.
  check_case "$fixture" "WOS-E4-TWO-PARTY-RETENTION" "E3" 1 "$POLICY_CUSTODY"
  # No policy at all: the TSA cannot be authenticated, so it caps at E3.
  check_case "$fixture" "no operator policy"         "E3" 1 ""
done

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "RELEASE ARTIFACT GATE: PASS"
  exit 0
fi
echo "::error::RELEASE ARTIFACT GATE: $FAILURES assertion(s) failed" >&2
exit 1
