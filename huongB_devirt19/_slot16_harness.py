#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_slot16_harness.py — validation harness + closed-form probe for slot16.

Data:
  _corr_data.json  : 13 rows {slot16(16B), rticket, mat(PSK 32B), seed(4B)}  <- key derivation set
  slot16_newphone_verified.json : 15 nonzero {query, slot16} (device 7666)

Goal: test whether slot16 = F(PSK, seed[, rticket]) has a closed form (esp. AES-based,
per _matched_tuple key_fact "deeper VM AES derivation"). If a construction reproduces all
13 (seed -> slot16) pairs, we have offline f. Standard-AES caveat: the .so uses a MODIFIED
key schedule (whitebox-ish), so a std-AES miss does NOT rule out AES structurally.
"""
import json, hashlib, struct, itertools
from Crypto.Cipher import AES

CORR = json.load(open("_corr_data.json"))
PSK = bytes.fromhex(CORR[0]["mat"])  # c02f250f... (constant across all rows)

PAIRS = []  # (seed4, slot16, rticket)
for r in CORR:
    PAIRS.append((bytes.fromhex(r["seed"]), bytes.fromhex(r["slot16"]), int(r["rticket"])))


def _seed_blocks(seed4, rticket):
    """Candidate 16-byte plaintext/blocks built from the 4-byte seed (+ optional rticket)."""
    rt_le = struct.pack("<Q", rticket)
    rt_be = struct.pack(">Q", rticket)
    return {
        "seed*4": seed4 * 4,
        "seed|z12": seed4 + b"\x00" * 12,
        "z12|seed": b"\x00" * 12 + seed4,
        "seed|z": (seed4 + b"\x00" * 12)[:16],
        "seed_rev*4": seed4[::-1] * 4,
        "seed|rtle|z4": (seed4 + rt_le + b"\x00" * 4),
        "seed|rtbe|z4": (seed4 + rt_be + b"\x00" * 4),
        "rtle|rtle": rt_le + rt_le,
        "seed*4^psk16": bytes(a ^ b for a, b in zip(seed4 * 4, PSK[:16])),
    }


def _keys():
    """Candidate 16-byte AES keys derived from PSK."""
    return {
        "psk[:16]": PSK[:16],
        "psk[16:]": PSK[16:],
        "md5(psk)": hashlib.md5(PSK).digest(),
        "md5(psk[:16])": hashlib.md5(PSK[:16]).digest(),
        "md5(psk[16:])": hashlib.md5(PSK[16:]).digest(),
        "sha256(psk)[:16]": hashlib.sha256(PSK).digest()[:16],
        "psk[:16]^psk[16:]": bytes(a ^ b for a, b in zip(PSK[:16], PSK[16:])),
    }


def _try_all():
    keys = _keys()
    hits = []
    # AES ECB/CBC: block from seed, key from PSK  (and swapped: key from seed, block from PSK)
    for kname, k in keys.items():
        for row_i, (seed4, slot16, rt) in enumerate([PAIRS[0]]):  # test construction on row0 first
            blocks = _seed_blocks(seed4, rt)
            for bname, blk in blocks.items():
                # slot16 = AES_ECB_enc(key=PSK-key, pt=seed-block)
                if AES.new(k, AES.MODE_ECB).encrypt(blk) == slot16:
                    hits.append(("ECB enc", kname, bname))
                if AES.new(k, AES.MODE_ECB).decrypt(blk) == slot16:
                    hits.append(("ECB dec", kname, bname))
                # CBC with iv = other PSK half / md5
                for ivname, iv in (("psk[16:]", PSK[16:]), ("zero", b"\x00" * 16),
                                   ("md5psk", hashlib.md5(PSK).digest())):
                    if AES.new(k, AES.MODE_CBC, iv).encrypt(blk) == slot16:
                        hits.append(("CBC enc iv=%s" % ivname, kname, bname))
    return hits


def _hash_probes():
    """Non-AES closed forms over (PSK, seed) — quick sanity, first row."""
    seed4, slot16, rt = PAIRS[0]
    cands = {
        "md5(psk|seed)": hashlib.md5(PSK + seed4).digest(),
        "md5(seed|psk)": hashlib.md5(seed4 + PSK).digest(),
        "md5(psk[:16]|seed)": hashlib.md5(PSK[:16] + seed4).digest(),
        "sm256(psk|seed)[:16]": hashlib.sha256(PSK + seed4).digest()[:16],
        "sm256(seed|psk)[:16]": hashlib.sha256(seed4 + PSK).digest()[:16],
        "md5(psk|rtle)": hashlib.md5(PSK + struct.pack("<Q", rt)).digest(),
    }
    return [name for name, v in cands.items() if v == slot16]


def validate(fn, label="fn"):
    """Test an offline candidate fn(psk, seed4, rticket)->16B against all 13 pairs."""
    ok = 0
    for seed4, slot16, rt in PAIRS:
        try:
            if fn(PSK, seed4, rt) == slot16:
                ok += 1
        except Exception:
            pass
    print(f"[validate] {label}: {ok}/{len(PAIRS)} pairs match")
    return ok == len(PAIRS)


if __name__ == "__main__":
    print(f"PSK = {PSK.hex()}")
    print(f"{len(PAIRS)} (seed->slot16) pairs loaded\n")

    # structural look
    print("=== structure ===")
    for seed4, slot16, rt in PAIRS[:4]:
        print(f"  seed={seed4.hex()}  slot16={slot16.hex()}")
    # is slot16 ever == seed-repeated or a plain transform?
    print()

    print("=== hash probes (row0) ===")
    h = _hash_probes()
    print("  hits:", h or "none")
    print()

    print("=== AES construction probes (row0) ===")
    hits = _try_all()
    if hits:
        print("  ROW0 HITS:", hits)
        # confirm any row0 hit across ALL 13 pairs
        for mode, kname, bname in hits:
            keys = _keys()
            def mk(psk, seed4, rt, mode=mode, k=keys[kname], bname=bname):
                blk = _seed_blocks(seed4, rt)[bname]
                if mode.startswith("ECB enc"):
                    return AES.new(k, AES.MODE_ECB).encrypt(blk)
                if mode.startswith("ECB dec"):
                    return AES.new(k, AES.MODE_ECB).decrypt(blk)
                if mode.startswith("CBC enc"):
                    iv = {"psk[16:]": PSK[16:], "zero": b"\x00"*16, "md5psk": hashlib.md5(PSK).digest()}[mode.split("iv=")[1]]
                    return AES.new(k, AES.MODE_CBC, iv).encrypt(blk)
            validate(mk, f"{mode} key={kname} blk={bname}")
    else:
        print("  no standard-AES construction matched row0 "
              "(consistent with modified/whitebox key-schedule -> native emulation needed)")
