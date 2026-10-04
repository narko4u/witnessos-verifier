# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WitnessOS Verifier — CLI.

Usage:
    witnessos-verifier verify ./evidence-bundle/
    witnessos-verifier --version
"""

import sys
from pathlib import Path

import click

from . import __version__
from .verifier import verify, VerifyError


@click.group()
@click.version_option(version=__version__, prog_name="witnessos-verifier")
def main():
    """WitnessOS™ Verifier — Independently verify AI action evidence bundles.

    This verifier reads WitnessOS evidence bundles and cryptographically
    checks event signatures, hash chains, and signed batch/Merkle binding.
    E4 requires an operator trust policy, an authenticated RFC 3161 timestamp,
    and an intact WORM evidence copy. A signed retention receipt is recorded as
    an attribute and required only where the policy sets require_retention.

    No gateway, credential broker, or key management code is included.
    """
    pass


@main.command()
@click.argument("bundle_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print PASS/FAIL")
@click.option("--alpha", "alpha_mode", is_flag=True, help="Alpha mode: cap max evidence grade at E3")
@click.option('--trust-policy', type=click.Path(exists=True, dir_okay=False, path_type=Path), help='Operator policy outside the bundle')
@click.option('--tsa-url', help='Expected TSA URL from operator configuration')
@click.option('--expected-nonce', type=int, help='Nonce retained from the original timestamp request')
def verify_cmd(bundle_path: Path, output_json: bool, quiet: bool, alpha_mode: bool = False,
               trust_policy=None, tsa_url=None, expected_nonce=None):
    """Verify a WitnessOS evidence bundle.

    BUNDLE_PATH: Path to the evidence bundle directory containing
    events/, keys.json, case_manifest.json, batch_manifest.json,
    timestamp/, and worm/.
    """
    try:
        from .trust_policy import TrustPolicy
        if trust_policy and trust_policy.resolve().is_relative_to(bundle_path.resolve()):
            raise VerifyError('Trust policy must be provisioned outside the evidence bundle')
        policy = TrustPolicy.from_json(trust_policy) if trust_policy else None
        result = verify(bundle_path, alpha_mode=alpha_mode, trust_policy=policy,
                        tsa_url=tsa_url, expected_nonce=expected_nonce)
    except (VerifyError, ValueError, TypeError, OSError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    if output_json:
        import json
        output = {
            "valid": result.valid,
            "grade": result.evidence_grade,
            "events": len(result.events),
            "chain_valid": result.chain_result.valid if result.chain_result else None,
            "ledger_valid": result.ledger_result.sequence_monotonic if result.ledger_result else None,
            "manifest_valid": result.manifest_result.valid if result.manifest_result else None,
            "timestamp_valid": result.timestamp_result.valid if result.timestamp_result else None,
            "timestamp_signature_verified": result.timestamp_result.signature_verified if result.timestamp_result else False,
            "timestamp_trust_verified": result.timestamp_result.trust_verified if result.timestamp_result else False,
            "retention_verified": result.worm_result.retention_verified if result.worm_result else False,
            "worm_valid": result.worm_result.valid if result.worm_result else None,
            "errors": result.errors,
            "warnings": result.warnings,
        }
        click.echo(json.dumps(output, indent=2))
    elif quiet:
        if result.valid:
            click.echo("PASS")
        else:
            click.echo("FAIL")
            for err in result.errors:
                click.echo(f"  {err}", err=True)
    else:
        click.echo(result.summary())

        if result.warnings:
            click.echo(f"\nWarnings ({len(result.warnings)}):")
            for w in result.warnings:
                click.echo(f"  ⚠ {w}")

        if result.grade:
            click.echo(f"\nRequirements met:")
            for req in result.grade.requirements_met:
                click.echo(f"  ✓ {req}")
            if result.grade.requirements_missing:
                click.echo(f"Requirements not met:")
                for req in result.grade.requirements_missing:
                    click.echo(f"  ✗ {req}")

    # Exit code: 0 if valid, 1 if invalid
    sys.exit(0 if result.valid else 1)


@main.command(name="verify-engine")
@click.argument("record_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--keys", "keys_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to keys.json. Defaults to <record_dir>/keys.json")
@click.option("--json", "output_json", is_flag=True, help="Output the verdict as JSON")
def verify_engine_cmd(record_dir: Path, keys_path, output_json: bool):
    """Verify a record produced by the WitnessOS engine, with the engine ABSENT.

    RECORD_DIR holds manifest.json, keys.json and leaves.json. Nothing here calls the
    engine or any service. The signatures are checked against the public keys carried in
    the record, offline, so a counterparty can verify a receipt without trusting us.

    Exit code 0 when the signatures verify and the anchor holds, 1 otherwise.
    """
    import json as _json

    from .engine_native import verify_engine_anchor, verify_engine_manifest

    manifest_path = record_dir / "manifest.json"
    keys_file = keys_path or (record_dir / "keys.json")
    leaves_file = record_dir / "leaves.json"
    for required in (manifest_path, keys_file):
        if not required.exists():
            click.echo(f"Missing {required}", err=True)
            sys.exit(1)

    manifest = _json.loads(manifest_path.read_text())
    keys = {k["key_id"]: k for k in _json.loads(keys_file.read_text())}
    leaves = []
    if leaves_file.exists():
        leaves = [x["global_event_hash"] for x in _json.loads(leaves_file.read_text()).get("leaves", [])]

    try:
        import witnessos                      # noqa: F401
        independent = False
    except ImportError:
        independent = True

    sig = verify_engine_manifest(manifest, keys)
    anchor = verify_engine_anchor(manifest, leaves) if leaves else {"valid": None, "errors": []}
    ok = bool(sig["valid"]) and anchor.get("valid") is not False

    if output_json:
        click.echo(_json.dumps({
            "batch_id": manifest.get("batch_id"), "suite": manifest.get("sig_algorithm"),
            "engine_absent": independent, "signature": sig, "anchor": anchor,
        }, indent=2, default=str))
        sys.exit(0 if ok else 1)

    click.echo("WitnessOS engine record")
    click.echo(f"  batch          {manifest.get('batch_id')}")
    click.echo(f"  suite          {manifest.get('sig_algorithm')}")
    click.echo(f"  primary key    {manifest.get('signer_key_id')}")
    click.echo(f"  counter key    {manifest.get('countersigner_key_id')}")
    click.echo(f"  leaves         {len(leaves)}")
    click.echo()
    click.echo(f"  signature      {'VALID' if sig['valid'] else 'INVALID'}"
               + (f"   halves={sig.get('halves')}" if sig.get("halves") else ""))
    for err in sig.get("errors", []):
        click.echo(f"    {err}", err=True)
    if anchor.get("valid") is not None:
        click.echo(f"  merkle anchor  {'VALID' if anchor['valid'] else 'INVALID'}")
        for err in anchor.get("errors", []):
            click.echo(f"    {err}", err=True)
    click.echo()
    click.echo(f"  engine absent  {independent}"
               + ("" if independent else "  (installed here, so NOT an independent check)"))
    click.echo()
    click.echo(f"RESULT: {'VERIFIED' if ok else 'NOT VERIFIED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
