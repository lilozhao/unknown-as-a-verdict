#!/usr/bin/env python3
"""Derive the three gap cases from the contract cases, and write cases/manifest.json.

The contract cases are copied from upstream byte-for-byte; their sha256 is
recorded here so a reader can check nothing was edited. The gap cases are
derived from them by exactly one change each, stated in the file itself.

Run:  python tools/make_gap_cases.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.bip340 import lift_x, nostr_event_id  # noqa: E402

CONTRACT = ROOT / "cases" / "contract"
GAP = ROOT / "cases" / "gap"

UPSTREAM = {
    "repo": "babyblueviper1/preaction-governance-conformance",
    "commit": "c63208dca83c2b6e5020449e55ea6f7336717c5e",
    "path": "examples/ag2-beta",
    "license": "MIT",
    "retrieved": "2026-10-27",
}

CONTRACT_EXPECT = {
    "matches.json": ("released/attestation_bound_and_verified",) * 2,
    "mismatch.json": ("blocked/attestation_intent_ref_mismatch",) * 2,
    "missing.json": ("blocked/required_attestation_missing",) * 2,
}

UPSTREAM_NAME = {
    "matches.json": "external_attestation_matches_intent_ref.json",
    "mismatch.json": "external_attestation_intent_ref_mismatch.json",
    "missing.json": "external_attestation_missing_where_required.json",
}


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(name: str) -> dict:
    return json.loads((CONTRACT / name).read_text())


def write_gap(name: str, fx: dict) -> None:
    (GAP / f"{name}.json").write_text(json.dumps(fx, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote cases/gap/{name}.json")


# ── gap-1: the policy block is absent ─────────────────────────────────────────
g1 = copy.deepcopy(load("missing.json"))
g1.pop("policy", None)
g1.update(
    {
        "fixture": "policy_absent",
        "derived_from": "cases/contract/missing.json",
        "derivation": "removed the top-level `policy` block; no other field changed",
        "why_this_input": (
            "The contract reads policy.requires_attestation; when the policy was never "
            "stated, 'attestation not required' and 'requirement unknown' are different "
            "facts but reach the same branch."
        ),
    }
)
write_gap("policy_absent", g1)

# ── gap-2: pubkey is 32 bytes but not a curve point ───────────────────────────
x = 0
while lift_x(x) is not None:
    x += 1
pubkey = f"{x:064x}"

g2 = copy.deepcopy(load("matches.json"))
g2["external_attestation"]["signed_event"]["pubkey"] = pubkey
_ev = g2["external_attestation"]["signed_event"]
_ev["id"] = nostr_event_id(_ev)  # id integrity holds; only the curve check can fail
g2.update(
    {
        "fixture": "pubkey_unresolvable",
        "derived_from": "cases/contract/matches.json",
        "derivation": (
            "replaced signed_event.pubkey with 32 zero bytes and recomputed signed_event.id, "
            "so NIP-01 id integrity still holds"
        ),
        "why_this_input": (
            "32 bytes is a well-formed x-only pubkey; this one simply has no point on "
            "secp256k1. Nothing shows the signature is wrong — the verifier cannot resolve "
            "the key. Key rotation, an unknown algorithm generation, or an unreachable "
            "identity registry all land here."
        ),
    }
)
write_gap("pubkey_unresolvable", g2)

# ── gap-3: pubkey is not hex at all ───────────────────────────────────────────
g3 = copy.deepcopy(load("matches.json"))
g3["external_attestation"]["signed_event"]["pubkey"] = "zz-not-hex"
_ev = g3["external_attestation"]["signed_event"]
_ev["id"] = nostr_event_id(_ev)  # NIP-01 treats pubkey as an opaque string
g3.update(
    {
        "fixture": "field_not_hex",
        "derived_from": "cases/contract/matches.json",
        "derivation": (
            "replaced signed_event.pubkey with a non-hex string and recomputed signed_event.id, "
            "so id integrity still holds at the point of decoding"
        ),
        "why_this_input": (
            "The schema types pubkey as a string. Decoding it raises before the contract can "
            "produce any verdict, so this input yields no record at all."
        ),
    }
)
write_gap("field_not_hex", g3)

# ── manifest ─────────────────────────────────────────────────────────────────
cases = []
for name in ("matches.json", "mismatch.json", "missing.json"):
    cases.append(
        {
            "file": f"cases/contract/{name}",
            "kind": "contract",
            "upstream_file": UPSTREAM_NAME[name],
            "sha256": sha256_file(CONTRACT / name),
            "expect_binary": CONTRACT_EXPECT[name][0],
            "expect_quaternary": CONTRACT_EXPECT[name][1],
        }
    )

GAP_EXPECT = {
    "policy_absent.json": ("released/no_attestation_required", "unknown/policy_undetermined"),
    "pubkey_unresolvable.json": (
        "blocked/attestation_signature_invalid",
        "unknown/attestation_key_unresolvable",
    ),
    "field_not_hex.json": ("CRASH/ValueError", "unknown/attestation_unparseable"),
}

for name, (b, q) in GAP_EXPECT.items():
    cases.append(
        {
            "file": f"cases/gap/{name}",
            "kind": "gap",
            "derived_from": f"cases/contract/{name.replace('policy_absent', 'missing').replace('pubkey_unresolvable', 'matches').replace('field_not_hex', 'matches')}",
            "sha256": sha256_file(GAP / name),
            "expect_binary": b,
            "expect_quaternary": q,
        }
    )

manifest = {"upstream": UPSTREAM, "cases": cases}
(ROOT / "cases" / "manifest.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
)
print("wrote cases/manifest.json")
