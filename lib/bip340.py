"""Minimal BIP-340 Schnorr verification and NIP-01 event id — standard library only.

Deliberately independent of any upstream implementation: if this file had been
copied from the suite under test, the results below would only restate that
suite's behaviour. Written from BIP-340 and NIP-01 directly.

Public algorithms, no third-party dependencies, ~90 lines.
"""
from __future__ import annotations

import hashlib
import json

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def lift_x(x: int):
    """Point with this x and even y, or None if no such point exists."""
    if x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)  # P == 3 (mod 4)
    if (y * y) % P != c:
        return None
    return (x, y if y % 2 == 0 else P - y)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(pt, k: int):
    acc = None
    while k:
        if k & 1:
            acc = point_add(acc, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return acc


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def schnorr_verify(msg32: bytes, pubkey32: bytes, sig64: bytes) -> bool:
    """BIP-340. Returns False — never raises — for every malformed input."""
    if len(msg32) != 32 or len(pubkey32) != 32 or len(sig64) != 64:
        return False
    pt = lift_x(int.from_bytes(pubkey32, "big"))
    if pt is None:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge", sig64[:32] + pubkey32 + msg32), "big"
    ) % N
    big_r = point_add(point_mul(G, s), point_mul(pt, N - e))
    if big_r is None or big_r[1] % 2 != 0 or big_r[0] != r:
        return False
    return True


def nostr_event_id(event: dict) -> str:
    """NIP-01: sha256 of the canonical [0,pubkey,created_at,kind,tags,content] serialization."""
    serial = json.dumps(
        [
            0,
            str(event["pubkey"]).lower(),
            int(event["created_at"]),
            int(event["kind"]),
            event.get("tags") or [],
            str(event["content"]),
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()
