# Provenance

Every file here is either copied from upstream with its hash recorded, or derived from
such a copy by one stated change.

## Upstream

| | |
|---|---|
| repository | `babyblueviper1/preaction-governance-conformance` |
| commit | `c63208dca83c2b6e5020449e55ea6f7336717c5e` (2026-10-25) |
| path | `examples/ag2-beta/` |
| license | MIT, © 2026 babyblueviper1 |
| retrieved | 2026-10-27 |

## Contract cases — copied, unmodified

| file here | upstream file | sha256 |
|---|---|---|
| `cases/contract/matches.json` | `external_attestation_matches_intent_ref.json` | `9e9c556d…f192a0` |
| `cases/contract/mismatch.json` | `external_attestation_intent_ref_mismatch.json` | `83a0ddc4…5fa36e3` |
| `cases/contract/missing.json` | `external_attestation_missing_where_required.json` | `be256375…e8b9588` |

Full hashes are in `cases/manifest.json`. `check.py` compares every file against them and
exits non-zero on any drift, so an edited copy cannot pass silently.

These three files were not normalised, reformatted, or re-serialised. Byte identity is the
point: it is what lets the comparison claim that upstream's own expectations are being
reproduced rather than re-derived.

## Gap cases — derived, one change each

| file here | derived from | the change |
|---|---|---|
| `cases/gap/policy_absent.json` | `contract/missing.json` | removed the top-level `policy` block |
| `cases/gap/pubkey_unresolvable.json` | `contract/matches.json` | `signed_event.pubkey` → 32 zero bytes; `signed_event.id` recomputed so NIP-01 integrity holds |
| `cases/gap/field_not_hex.json` | `contract/matches.json` | `signed_event.pubkey` → `"zz-not-hex"`; `signed_event.id` recomputed the same way |

`tools/make_gap_cases.py` regenerates all three from `cases/contract/` and rewrites the
manifest. Running it twice produces identical files.

Each derived file carries `derived_from`, `derivation`, and `why_this_input` fields so the
change is readable without this document.

## The verifier is written here, not copied

`lib/bip340.py` implements BIP-340 verification and NIP-01 event-id derivation from the
specifications. It is not taken from upstream's vendored `_bip340_nostr.py`.

This matters for the argument: if the verifier were copied, a passing result would only
restate upstream's code. Written independently, the contract cases passing means two
separate implementations of the same standard agree — the `matches` case reaches
`released/attestation_bound_and_verified`, which requires a positive signature check to
succeed.

`lib/contract.py::decide_binary` is a branch-for-branch transcription of upstream's
`decide()`, including its failure mode: a non-hex `pubkey` raises out of `bytes.fromhex`
instead of returning `False`. That behaviour is one of the three things under test, so it
is preserved rather than guarded.

## Reproducing the comparison

```bash
python check.py                          # six cases, exit 0 only if all match

sha256sum cases/contract/*.json          # compare against manifest.json
```

To check the derivation by hand, diff any `cases/gap/*.json` against its `derived_from`
file: exactly one field differs, plus the three provenance fields.
