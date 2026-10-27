"""The AG2 Beta external-attestation contract, and the same contract with one more value.

`decide_binary` reproduces the decision procedure of
`examples/ag2-beta/check_triple.py::decide` (upstream commit c63208d, MIT),
branch for branch. It is here so the comparison runs on one implementation.

`decide_quaternary` keeps every branch that already produced a verdict, and adds
`unknown` only where the binary contract has no answer at all.

Nothing here reads a producer-supplied label. Both functions derive the verdict
from the bytes, which is the property the upstream README asks for.
"""
from __future__ import annotations

import hashlib

from .bip340 import lift_x, nostr_event_id, schnorr_verify

RELEASED = "released"
BLOCKED = "blocked"
UNKNOWN = "unknown"


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def attestation_is_valid_and_bound(att: dict, intent_ref: str):
    """(signature_valid, binds_intent_ref) — two independent dimensions.

    Kept structurally identical to upstream, including its failure mode:
    a non-hex `pubkey` raises out of `bytes.fromhex` rather than returning False.
    That is the behaviour under test, not an oversight here.
    """
    ev = att.get("signed_event") or {}
    sig_valid = nostr_event_id(ev) == ev.get("id") and schnorr_verify(
        bytes.fromhex(ev["id"]),
        bytes.fromhex(ev["pubkey"]),
        bytes.fromhex(ev["sig"]),
    )
    binds = att.get("artifact_hash") == intent_ref
    return sig_valid, binds


def decide_binary(fx: dict) -> tuple[str, str]:
    """Upstream procedure, verbatim. May raise."""
    pa = fx["proposed_action"]

    if sha256_hex(pa["canonical_input"]["canonical_bytes_utf8"]) != pa["intent_ref"]:
        return BLOCKED, "intent_ref_recompute_failed"
    intent_ref = pa["intent_ref"]

    att = fx.get("external_attestation")
    if att is None:
        if fx.get("policy", {}).get("requires_attestation"):
            return BLOCKED, "required_attestation_missing"
        return RELEASED, "no_attestation_required"

    sig_valid, binds = attestation_is_valid_and_bound(att, intent_ref)
    if not sig_valid:
        return BLOCKED, "attestation_signature_invalid"
    if not binds:
        return BLOCKED, "attestation_intent_ref_mismatch"
    return RELEASED, "attestation_bound_and_verified"


def decide_quaternary(fx: dict) -> tuple[str, str]:
    """Same contract, three additional branches. Never raises."""
    pa = fx["proposed_action"]

    # unchanged
    if sha256_hex(pa["canonical_input"]["canonical_bytes_utf8"]) != pa["intent_ref"]:
        return BLOCKED, "intent_ref_recompute_failed"
    intent_ref = pa["intent_ref"]

    policy = fx.get("policy")
    requires = policy.get("requires_attestation") if isinstance(policy, dict) else None

    att = fx.get("external_attestation")

    # absence of evidence: unchanged when the requirement was stated either way;
    # NEW when the requirement was never stated.
    if att is None:
        if requires is True:
            return BLOCKED, "required_attestation_missing"
        if requires is False:
            return RELEASED, "no_attestation_required"
        return UNKNOWN, "policy_undetermined"

    ev = att.get("signed_event") or {}

    # NEW: the artifact cannot be parsed. No verdict was possible before.
    try:
        msg = bytes.fromhex(ev["id"])
        pubkey = bytes.fromhex(ev["pubkey"])
        sig = bytes.fromhex(ev["sig"])
    except (KeyError, TypeError, ValueError):
        return UNKNOWN, "attestation_unparseable"

    # NEW: an identity that cannot be resolved is not a wrong signature.
    if len(pubkey) != 32 or lift_x(int.from_bytes(pubkey, "big")) is None:
        return UNKNOWN, "attestation_key_unresolvable"

    # unchanged from here down
    if len(msg) != 32 or len(sig) != 64:
        return BLOCKED, "attestation_signature_invalid"
    if nostr_event_id(ev) != ev.get("id"):
        return BLOCKED, "attestation_signature_invalid"
    if not schnorr_verify(msg, pubkey, sig):
        return BLOCKED, "attestation_signature_invalid"
    if att.get("artifact_hash") != intent_ref:
        return BLOCKED, "attestation_intent_ref_mismatch"
    return RELEASED, "attestation_bound_and_verified"
