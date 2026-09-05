#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _mssdk_battery.py — decryption battery for the mssdk wire blobs (notes/73 §4-§5).
#   Blobs: cap.noindex/gettoken_wire/blobs.json (from _mssdk_blobs.py; git-ignored).
#   All blobs are len%16==0 -> try AES-128/256-ECB, AES-CBC(iv=0), SM4-ECB with
#   device-stable key candidates. Oracle: zlib magic / protobuf-sane / printable.
# Secrets stay in cap.noindex/ (stdout prints labels + verdicts only, never values).
import hashlib, json, os, string, sys

from Crypto.Cipher import AES

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# SM4 raw (KAT-validated, imported from _f_blockcipher_test.py — it loads _corr_data.json
# relative to ITS OWN dir, so chdir around the import)
_cwd = os.getcwd()
os.chdir(SCRIPT_DIR)
from _f_blockcipher_test import sm4_decrypt as _sm4_dec
os.chdir(_cwd)


def sm4_ecb_dec(key16, data):
    out = bytearray()
    for off in range(0, len(data) - len(data) % 16, 16):
        out += _sm4_dec(key16, data[off:off + 16])
    return bytes(out)


def oracle(pt):
    """Return (verdict, why) if plaintext looks structured, else (None, '')."""
    if not pt:
        return None, ""
    if pt[:1] == b"\x78" and pt[1:2] in (b"\x01", b"\x9c", b"\xda", b"\x5e"):
        return "ZLIB", "zlib magic %s" % pt[:2].hex()
    printable = sum(1 for b in pt[:64] if 32 <= b < 127 or b in (9, 10, 13))
    if printable >= 58:
        return "PRINT", "%d/64 printable head" % printable
    if pt[:1] in (b"{", b"["):
        return "JSON", "brace head"
    # protobuf sanity: field 1-40, wt 0/2/5, small leading varint
    t = pt[0]
    if 8 <= (t >> 3) <= 40 and (t & 7) in (0, 2, 5):
        return "PB?", "tag %02x" % t
    return None, ""


def load_keys():
    """(label, key-bytes) candidates — device-stable material only."""
    ks = []
    sign_key = bytes.fromhex(
        "c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
    ks.append(("SIGN_KEY[32]", sign_key))
    ks.append(("SIGN_KEY[:16]", sign_key[:16]))
    ks.append(("SIGN_KEY[16:]", sign_key[16:]))
    ks.append(("zeros16", b"\x00" * 16))
    ks.append(("zeros32", b"\x00" * 32))
    for name in ("sdi", "ecneuq", "semithc"):
        ks.append(("MD5(1233-0-1-%s)" % name,
                   hashlib.md5(("1233-0-1-" + name).encode()).digest()))
    ks.append(("MD5(SHA1(sdi_v2))",
               hashlib.md5(hashlib.sha1(b"sdi_v2").hexdigest().encode()).digest()))
    ks.append(("SHA1(sdi_v2)[:16]", hashlib.sha1(b"sdi_v2").digest()[:16]))
    ks.append(("MD5(sdi_v2)", hashlib.md5(b"sdi_v2").digest()))
    # device-stable store values (phone_sync, git-ignored)
    props = {}
    pf = os.path.join(SCRIPT_DIR, "..", "cap.noindex", "secdump", "store_dump.properties")
    if os.path.exists(pf):
        for line in open(pf):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                props[k] = v
    def add_str(label, s):
        if s and not s.isspace():
            b = s.encode("latin1")
            ks.append((label + "[ascii]", b[:32].ljust(32, b"\x00")[:32]))
            ks.append((label + "[:16ascii]", b[:16]))
            ks.append((label + "[md5]", hashlib.md5(b).digest()))
            try:
                h = bytes.fromhex(s)
                if len(h) >= 16:
                    ks.append((label + "[hex:16]", h[:16]))
                    if len(h) >= 32:
                        ks.append((label + "[hex:32]", h[:32]))
            except ValueError:
                pass
    for k in ("rtk2_ms", "kiid", "rdk2_ms", "dyn_seed", "device_token"):
        if k in props:
            add_str(k, props[k])
    return ks


def main():
    bj = os.path.join(SCRIPT_DIR, "..", "cap.noindex", "gettoken_wire", "blobs.json")
    if not os.path.exists(bj):
        sys.exit("ERROR: %s missing (run _mssdk_blobs.py first)" % bj)
    blobs = json.load(open(bj))
    keys = load_keys()
    print("key candidates: %d" % len(keys))
    hits = 0
    for b in blobs.get("blobs", []):
        data = bytes.fromhex(b["hex"])
        label = "%s f%d len=%d" % (b["file"].split("_")[-1], b["field"], len(data))
        best = []
        for kl, kb in keys:
            if len(kb) not in (16, 24, 32):
                continue
            try:
                pt = AES.new(kb, AES.MODE_ECB).decrypt(data)
                v, why = oracle(pt)
                if v:
                    best.append(("AES%d-ECB/%s" % (len(kb) * 8, kl), v, why, pt[:24].hex()))
                pt = AES.new(kb, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(data)
                v, why = oracle(pt)
                if v:
                    best.append(("AES%d-CBC0/%s" % (len(kb) * 8, kl), v, why, pt[:24].hex()))
            except Exception:
                pass
            if len(kb) == 16:
                try:
                    pt = sm4_ecb_dec(kb, data)
                    v, why = oracle(pt)
                    if v:
                        best.append(("SM4-ECB/%s" % kl, v, why, pt[:24].hex()))
                except Exception:
                    pass
        if best:
            hits += 1
            print("%s: %d candidate hits" % (label, len(best)))
            for c in best[:6]:
                print("   ", c)
        else:
            print("%s: no hit" % label)
    print("hits: %d/%d blobs" % (hits, len(blobs.get("blobs", []))))


if __name__ == "__main__":
    main()
