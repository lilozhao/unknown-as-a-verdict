#!/usr/bin/env python3
"""Run six cases against the AG2 Beta external-attestation contract.

Three are the contract's own cases, copied byte-for-byte; they must reproduce
upstream's expected verdicts. Three are derived inputs the contract does not
name; they are what this repository is about.

    python check.py

Exit 0 only if every case matches its recorded expectation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.contract import decide_binary, decide_quaternary  # noqa: E402

MANIFEST = json.loads((ROOT / "cases" / "manifest.json").read_text())
UP = MANIFEST["upstream"]


def run(fn, fx):
    try:
        return "/".join(fn(fx))
    except Exception as exc:
        return f"CRASH/{type(exc).__name__}"


def main() -> int:
    print()
    print("unknown as a verdict - 6 cases against the AG2 Beta external-attestation contract")
    print(f"upstream: {UP['repo']} @ {UP['commit'][:7]} ({UP['license']}), {UP['path']}")
    print()

    hdr = ("kind", "case", "binary contract", "+ unknown", "")
    rows, failures = [], 0

    for c in MANIFEST["cases"]:
        fx = json.loads((ROOT / c["file"]).read_text())
        b = run(decide_binary, fx)
        q = run(decide_quaternary, fx)
        ok = b == c["expect_binary"] and q == c["expect_quaternary"]
        failures += 0 if ok else 1
        rows.append((c["kind"], Path(c["file"]).stem, b, q, "PASS" if ok else "FAIL"))

    w = [max(len(str(r[i])) for r in rows + [hdr]) for i in range(4)]
    line = f"{'kind':<8}  {'case':<20}  {'binary contract':<{w[2]}}  {'+ unknown':<{w[3]}}  "
    print(line + "check")
    print("-" * (len(line) + 5))
    for kind, name, b, q, verdict in rows:
        print(f"{kind:<8}  {name:<20}  {b:<{w[2]}}  {q:<{w[3]}}  {verdict}")
    print()

    contract = [r for r in rows if r[0] == "contract"]
    gap = [r for r in rows if r[0] == "gap"]
    compat = all(r[2] == r[3] for r in contract)

    print(f"upstream cases reproduced : {sum(1 for r in contract if r[4] == 'PASS')}/{len(contract)}")
    print(f"derived cases answered    : {sum(1 for r in gap if r[4] == 'PASS')}/{len(gap)}")
    print(f"verdicts changed upstream : {'none' if compat else 'YES - regression'}")
    print()
    print("A case is 'answered' when the contract returns a value for it and that value")
    print("matches what the file recorded before the run. For the three derived cases the")
    print("recorded value under the binary contract is the problem being reported:")
    print("one releases, one blocks as a bad signature, one raises.")
    print()
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
