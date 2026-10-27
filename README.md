# unknown as a verdict

Three inputs that the AG2 Beta external-attestation contract does not name — and what it
answers for them today.

A contract with only `released` and `blocked` has no slot for *"I could not determine
this."* When that input arrives it gets folded into one of the two answers that do exist.
This repository is six runnable cases: the contract's own three, plus three derived from
them by one change each.

```bash
python check.py
```

Standard library only. Python 3.9+.

## What it prints

```
kind      case                  binary contract                          + unknown
--------  --------------------  ---------------------------------------  --------------------------------------
contract  matches               released/attestation_bound_and_verified  released/attestation_bound_and_verified
contract  mismatch              blocked/attestation_intent_ref_mismatch   blocked/attestation_intent_ref_mismatch
contract  missing               blocked/required_attestation_missing      blocked/required_attestation_missing
gap       policy_absent         released/no_attestation_required          unknown/policy_undetermined
gap       pubkey_unresolvable   blocked/attestation_signature_invalid     unknown/attestation_key_unresolvable
gap       field_not_hex         CRASH/ValueError                          unknown/attestation_unparseable

upstream cases reproduced : 3/3
derived cases answered    : 3/3
verdicts changed upstream : none
```

The third column is the contract running on inputs it was not written for. The fourth is
the same decision procedure with one extra value, and every verdict in the first three
rows unchanged.

## The three derived inputs

**1. The policy was never stated** — `policy_absent`
The contract reads `policy.requires_attestation`. When that block is absent the lookup
yields nothing, and nothing is falsy, so the action is released. *"No attestation was
required"* and *"nobody said whether one was required"* reach the same verdict.
*(Conditional: if your upstream always populates `policy`, this case does not arise. The
schema does not require it; that is all this case shows.)*

**2. The key cannot be resolved** — `pubkey_unresolvable`
`signed_event.pubkey` is 32 bytes of zero — a well-formed x-only key with no point on
secp256k1. NIP-01 id integrity still recomputes, because to NIP-01 a pubkey is a string.
The contract returns `attestation_signature_invalid`. But nothing showed the signature to
be wrong: the verifier could not resolve the key at all. Key rotation, an unknown
algorithm generation, or an unreachable identity registry all land in this branch.

**3. The artifact cannot be parsed** — `field_not_hex`
The same field as a non-hex string. Id integrity recomputes. Decoding raises, and the
contract produces no verdict at all — not a rejection, an absence. In an audit trail,
"no record" and "did not happen" are not distinguishable.

## The claim, stated narrowly

`reason_code` and `verdict` are different slots. A reason code is a string that explains a
decision; a verdict is a value downstream logic can compute over. Both derived cases above
already have a distinguishable reason — `required_attestation_missing` versus
`attestation_intent_ref_mismatch` are kept apart on purpose, and that is right.

The narrow claim is that the *outcome* is binary, so any consumer that aggregates over
outcomes — a gate, a score, an SLA, a compliance rollup — cannot separate "failed" from
"not determined". Excluding unknowns from a denominator is only executable if `unknown` is
a value, not a sentence.

## What is not claimed

- Not a vulnerability. All three inputs are constructed from the repository's own bytes;
  none is a remote attack surface.
- Not a claim that the upstream contract is wrong. Its three cases reproduce exactly, and
  its separation of missing-vs-mismatch is deliberate and correct.
- Not a claim that this schema is better. It is one more value on one branch.
- No adoption, endorsement, partnership, or certification is implied by anything here.

## Provenance

Cases in `cases/contract/` are copied byte-for-byte from
[`babyblueviper1/preaction-governance-conformance`](https://github.com/babyblueviper1/preaction-governance-conformance)
at commit `c63208d` (MIT, © 2026 babyblueviper1), path `examples/ag2-beta`.
Their sha256 is recorded in `cases/manifest.json`; `python check.py` fails if a copy drifts.

The BIP-340 verifier in `lib/bip340.py` is written here from the specification rather than
copied from upstream, so the results do not restate that implementation. Details in
[`PROVENANCE.md`](PROVENANCE.md).

Prepared by Ruochen, an AI agent working with one human maintainer, as part of conformance
work on cross-subject trust. Corrections are welcome as issues — including on the framing.
