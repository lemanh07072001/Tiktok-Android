#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# slot16_brute.py — note 34 §3. Try to reproduce slot16 offline as a closed form over
# per-request inputs, applying the note-33 §5 "wrong-input" lesson (hash the right OBJECT).
#
# INPUT: a JSON list of observations, each with (all optional except slot16):
#   { "slot16": "<32 hex>",           # REQUIRED. all-zero rows are skipped (nothing to fit)
#     "query":  "<k=v&...>",          # to pull ts/_rticket/iid/device_id/last_install_time
#     "d19":    "<64 hex>",           # report #19 (not needed for brute, kept for context)
#     "nonce13":"<hex>", "nonce14":"<hex>", "nonce15":"<hex>",  # report per-req nonces if captured
#     "ts":"..","_rticket":".." }     # optional explicit overrides
# The device-stable #18 (pskHash) default is note-33's value; override with --k18 for another device.
#
# A construction that matches slot16 for EVERY nonzero row = SOLVED (closed-form offline recipe).
# Usage:  python slot16_brute.py <observations.json> [--k18 <32hex>]
import sys, os, json, hmac
from _sm3 import sm3

K18_DEFAULT = "3ce2766b40195144a93b6c0ccc3e1307"  # note 33: device-stable #18 for device 7674923887225882119


def md5(b):
    import hashlib
    return hashlib.md5(b).digest()


def hmac_sm3(key, msg):
    return hmac.new(key, msg, lambda d=b"": _Sm3Wrap(d)).digest() if False else _hmac_generic(sm3, 64, key, msg)


def _hmac_generic(hfn, block, key, msg):
    if len(key) > block:
        key = hfn(key)
    key = key + b"\x00" * (block - len(key))
    o = bytes(k ^ 0x5c for k in key)
    i = bytes(k ^ 0x36 for k in key)
    return hfn(o + hfn(i + msg))


def bswap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def transforms(dig):
    # candidate 16-byte outputs derived from a digest
    return {
        "[:16]": dig[:16],
        "[-16:]": dig[-16:],
        "bswap4[:16]": bswap4(dig[:16]),
        "bswap4[-16:]": bswap4(dig[-16:]),
    }


def parse_query(q):
    d = {}
    for part in (q or "").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def inputs_for(obs, k18):
    """Return {label: bytes} candidate atoms for this observation."""
    qd = parse_query(obs.get("query", ""))
    ts = str(obs.get("ts") or qd.get("ts") or "")
    rt = str(obs.get("_rticket") or qd.get("_rticket") or "")
    iid = str(obs.get("iid") or qd.get("iid") or "")
    did = str(obs.get("device_id") or qd.get("device_id") or "")
    lit = str(obs.get("last_install_time") or qd.get("last_install_time") or "")
    a = {}
    a["k18"] = k18
    if ts:
        a["ts_ascii"] = ts.encode()
        try:
            n = int(ts)
            a["ts_le4"] = (n & 0xffffffff).to_bytes(4, "little")
            a["ts_be4"] = (n & 0xffffffff).to_bytes(4, "big")
            a["ts_le8"] = (n & (2**64 - 1)).to_bytes(8, "little")
        except ValueError:
            pass
    if rt:
        a["rticket_ascii"] = rt.encode()
    if iid:
        a["iid_ascii"] = iid.encode()
    if did:
        a["did_ascii"] = did.encode()
    if lit:
        a["lit_ascii"] = lit.encode()
    for nk in ("nonce13", "nonce14", "nonce15"):
        if obs.get(nk):
            try:
                a[nk] = bytes.fromhex(obs[nk])
            except ValueError:
                pass
    if obs.get("query"):
        a["query"] = obs["query"].encode()
    return a


# (hash-label, hash-fn) x (message template as tuple of atom-labels)
HASHES = [("sm3", sm3), ("md5", md5)]
MSG_TEMPLATES = [
    ("k18",),
    ("k18", "ts_ascii"), ("ts_ascii", "k18"),
    ("k18", "rticket_ascii"), ("rticket_ascii", "k18"),
    ("k18", "ts_le4"), ("k18", "ts_be4"), ("k18", "ts_le8"),
    ("query", "k18"), ("k18", "query"),
    ("k18", "nonce13"), ("k18", "nonce14"), ("k18", "nonce15"),
    ("nonce14",), ("nonce15",),
    ("ts_ascii",), ("rticket_ascii",),
    ("k18", "iid_ascii"), ("k18", "did_ascii"),
]
# keyed constructions: (label, keyatom, msgatoms)
HMAC_TEMPLATES = [
    ("hmac_sm3(k18; ts)", "k18", ("ts_ascii",)),
    ("hmac_sm3(k18; rticket)", "k18", ("rticket_ascii",)),
    ("hmac_sm3(k18; query)", "k18", ("query",)),
    ("hmac_md5(k18; ts)", "k18", ("ts_ascii",)),
    ("hmac_md5(k18; nonce14)", "k18", ("nonce14",)),
]


def build_msg(atoms, template):
    parts = []
    for name in template:
        if name not in atoms:
            return None
        parts.append(atoms[name])
    return b"".join(parts)


def main():
    if len(sys.argv) < 2:
        print("usage: python slot16_brute.py <observations.json> [--k18 <32hex>]")
        sys.exit(2)
    path = sys.argv[1]
    obs_all = json.load(open(path, encoding="utf-8"))

    # k18 (device-stable #18) resolution: --k18 flag > captured 'k18' in data > note-33 default.
    # IMPORTANT on a DIFFERENT phone: #18 is device-specific — do NOT reuse the old value.
    from collections import Counter
    k18 = None
    if "--k18" in sys.argv:
        k18 = sys.argv[sys.argv.index("--k18") + 1]
        src = "--k18 flag"
    else:
        cap = Counter(o["k18"] for o in obs_all if o.get("k18"))
        if cap:
            k18 = cap.most_common(1)[0][0]
            src = f"captured in data ({cap.most_common(1)[0][1]}x)"
        else:
            k18 = K18_DEFAULT
            src = "note-33 DEFAULT (old phone ce031603 — WRONG for a different phone!)"
    print(f"[*] k18 (#18) = {k18}  [{src}]")
    k18b = bytes.fromhex(k18)
    rows = []
    for o in obs_all:
        if "slot16" not in o:
            continue
        s = bytes.fromhex(o["slot16"])
        if s == b"\x00" * 16:
            continue  # zero rows carry no fit signal
        rows.append((o, s))
    print(f"[*] {len(rows)} nonzero-slot16 observations to fit (of {len(obs_all)} total)")
    if not rows:
        print("[!] no nonzero rows — need the nonzero-slot16 capture (see slot16_capture.js), "
              "not _report19_verified.json (all-zero).")
        return

    # tally: label -> match count
    tally = {}
    for o, s in rows:
        atoms = inputs_for(o, k18b)
        for hlab, hfn in HASHES:
            for tmpl in MSG_TEMPLATES:
                msg = build_msg(atoms, tmpl)
                if msg is None:
                    continue
                dig = hfn(msg)
                for tlab, out in transforms(dig).items():
                    if out == s:
                        lab = f"{hlab}({'||'.join(tmpl)}).{tlab}"
                        tally[lab] = tally.get(lab, 0) + 1
        for hlab, keyatom, mtmpl in HMAC_TEMPLATES:
            if keyatom not in atoms:
                continue
            msg = build_msg(atoms, mtmpl)
            if msg is None:
                continue
            hf = sm3 if "sm3" in hlab else md5
            blk = 64
            dig = _hmac_generic(hf, blk, atoms[keyatom], msg)
            for tlab, out in transforms(dig).items():
                if out == s:
                    tally[f"{hlab}.{tlab}"] = tally.get(f"{hlab}.{tlab}", 0) + 1

    if not tally:
        print("[-] no construction matched any row. slot16 is NOT a simple hash of these atoms.")
        print("    -> add captured nonces (#13/#14/#15) to the observations, or the answer is the")
        print("       flattened-builder derivation at 0x55950 over the session PSK (note 34 sec.2/6).")
        return
    n = len(rows)
    print("[+] matches (label: matched/total):")
    for lab, c in sorted(tally.items(), key=lambda kv: -kv[1]):
        flag = "  <<< SOLVED (all rows)" if c == n else ""
        print(f"    {lab}: {c}/{n}{flag}")


if __name__ == "__main__":
    main()
