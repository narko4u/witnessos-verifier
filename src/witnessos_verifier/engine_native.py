"""Verify a record produced by the WitnessOS engine, with the engine absent.

The engine and this verifier use different canonical forms. The engine signs its own
manifest field set, so this module reproduces that form rather than reformatting the
record. Signatures are verified exactly as the engine produced them.

Nothing here imports the engine. The canonicaliser below reimplements the engine's form
on stdlib json, and it has been proven byte-identical to the engine's own output for a
real hybrid manifest.
"""
import base64
import json
from typing import Any, Dict, List, Optional

from .merkle import build_merkle_tree
from .signatures import UnsupportedScheme, verify_signature

# The engine signs everything except these two, which are the signatures themselves.
ENGINE_EXCLUDED_FROM_SIGNING = ("signature", "countersignature")
# The engine omits an unstated claim rather than carrying a null.
ENGINE_CLAIMS = ("signer_key_id", "sig_algorithm", "countersigner_key_id")


def canonical_bytes(obj: Any) -> bytes:
    """The engine's canonical form: sorted keys, compact separators, ASCII escapes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def engine_signed_payload(manifest: Dict[str, Any]) -> bytes:
    """The bytes the engine signed, rebuilt from the manifest alone."""
    obj = {k: v for k, v in manifest.items() if k not in ENGINE_EXCLUDED_FROM_SIGNING}
    for claim in ENGINE_CLAIMS:
        if obj.get(claim) is None:
            obj.pop(claim, None)
    return canonical_bytes(obj)


def _bare_hex(value: str) -> str:
    """The engine prefixes hashes with sha256:. The bundle wants bare hex."""
    if not isinstance(value, str):
        return value
    return value.split(":", 1)[1] if value.startswith("sha256:") else value


def _half(algorithm: Optional[str], public_key_hex: str, message: bytes,
          signature: str, label: str, errors: List[str]) -> bool:
    """Verify one half. An unperformable scheme is a refusal, never a skip."""
    # The engine writes "<label>:<hex>". This verifier takes base64, so the label is
    # split off and the hex is converted. The label is not discarded quietly: where it
    # disagrees with the key's declared scheme, that is a refusal below.
    declared, _, body = str(signature).partition(":")
    if not body:
        declared, body = None, str(signature)
    try:
        signature_b64 = base64.b64encode(bytes.fromhex(body)).decode()
    except ValueError:
        errors.append(f"{label}: signature is not valid hex")
        return False
    if declared and algorithm and declared.strip().lower() != str(algorithm).strip().lower():
        errors.append(f"{label}: signature label {declared!r} disagrees with the key's scheme {algorithm!r}")
        return False
    try:
        if not verify_signature(algorithm, public_key_hex, message, signature_b64):
            errors.append(f"{label} invalid under scheme {algorithm}")
            return False
        return True
    except UnsupportedScheme as exc:
        errors.append(f"{label}: unsupported signature scheme {exc}")
        return False


def verify_engine_manifest(manifest: Dict[str, Any], keys: Dict[str, Any]) -> Dict[str, Any]:
    """Verify an engine manifest's signature, composite or not.

    Args:
        manifest: the engine's manifest, exactly as it wrote it.
        keys: key_id to a record carrying public_key_hex and algorithm.

    Returns a verdict dict. valid is True only when every requirement holds.
    """
    errors: List[str] = []
    suite = manifest.get("sig_algorithm")
    primary_id = manifest.get("signer_key_id")
    counter_id = manifest.get("countersigner_key_id")
    payload = engine_signed_payload(manifest)

    def pub(kid):
        rec = keys.get(kid)
        if rec is None:
            return None, None
        return rec.get("public_key_hex"), rec.get("algorithm")

    primary_hex, primary_alg = pub(primary_id)
    if primary_hex is None:
        errors.append(f"primary key {primary_id!r} not among the supplied keys")
        return {"valid": False, "errors": errors, "suite": suite}

    if suite is None:
        # A single-scheme record, which is what the engine wrote before the suite
        # dimension existed. Verified under the key's own declared algorithm.
        ok = _half(primary_alg, primary_hex, payload, manifest.get("signature", ""),
                   f"primary signature for {primary_id}", errors)
        return {"valid": ok and not errors, "errors": errors, "suite": None,
                "composite": False}

    labels = [p.strip().lower() for p in str(suite).split("+") if p.strip()]
    if len(labels) < 2:
        # A single declared scheme carrying an explicit label. That is what the
        # engine writes when exactly one ledger key is provisioned, which is the
        # default deployment and the state every deployment began in. It is not a
        # fault and not a downgrade claim: it is a record whose own manifest says
        # which one scheme signed it.
        #
        # Refusing it failed every classical record the engine still produces.
        # Guardrail 2 keeps the classical profile alive while the post-quantum one
        # is added, so the verifier has to verify it rather than reject it. The
        # suite is returned and printed, which is what keeps the classical
        # exposure visible instead of hidden.
        ok = _half(primary_alg, primary_hex, payload, manifest.get("signature", ""),
                   f"primary signature for {primary_id}", errors)
        declared_single = str(primary_alg).strip().lower()
        if declared_single not in labels:
            errors.append(
                f"suite {suite!r} does not match the key's declared scheme "
                f"{declared_single!r}")
        return {"valid": ok and not errors, "errors": errors, "suite": suite,
                "composite": False, "halves": {"primary": ok, "counter": False}}

    if not manifest.get("countersignature"):
        errors.append(f"suite {suite!r} is declared and no countersignature is present")
    if not counter_id:
        errors.append(f"suite {suite!r} is declared and no countersigner key is named")

    counter_hex = counter_alg = None
    if counter_id:
        counter_hex, counter_alg = pub(counter_id)
        if counter_hex is None:
            errors.append(f"countersigner key {counter_id!r} not among the supplied keys")
        elif counter_hex == primary_hex:
            errors.append("countersigner key is the primary key")

    # The suite has to agree with what the keys themselves declare. This is what
    # closes the swap: a signature from another key carries another algorithm.
    if counter_hex is not None:
        declared = {str(primary_alg).strip().lower(), str(counter_alg).strip().lower()}
        if declared != set(labels):
            errors.append(f"suite {suite!r} does not match the keys' declared schemes {sorted(declared)}")

    primary_ok = _half(primary_alg, primary_hex, payload, manifest.get("signature", ""),
                       f"primary signature for {primary_id}", errors)
    counter_ok = False
    if counter_hex is not None and manifest.get("countersignature"):
        counter_ok = _half(counter_alg, counter_hex, payload, manifest["countersignature"],
                           f"countersignature for {counter_id}", errors)

    return {
        "valid": primary_ok and counter_ok and not errors,
        "errors": errors,
        "suite": suite,
        "composite": True,
        "halves": {"primary": primary_ok, "counter": counter_ok},
    }


def verify_engine_anchor(manifest: Dict[str, Any], leaves: List[str]) -> Dict[str, Any]:
    """Recompute the Merkle root from the declared leaves and compare to the manifest.

    Option 1: the leaf is the engine's stored per-event hash, so the root is rebuilt
    from declared values rather than recomputed from event bytes. The engine's own
    build_batch does the same, which is why this is the form the record uses.
    """
    errors: List[str] = []
    if not leaves:
        return {"valid": False, "errors": ["no leaves supplied"], "recomputed": None}
    # The engine's leaves are already per-event hashes, so they are combined as
    # leaf hashes rather than re-hashed from event bytes.
    recomputed = build_merkle_tree([bytes.fromhex(_bare_hex(x)) for x in leaves]).hex()
    declared = _bare_hex(manifest.get("merkle_root", ""))
    got = _bare_hex(recomputed) if recomputed else None
    if got != declared:
        errors.append(f"Merkle root mismatch: recomputed {got} against declared {declared}")
    expected_count = manifest.get("leaf_count")
    if expected_count is not None and expected_count != len(leaves):
        errors.append(f"leaf count mismatch: manifest says {expected_count}, {len(leaves)} supplied")
    return {"valid": not errors, "errors": errors, "recomputed": got, "declared": declared}
