#!/usr/bin/env python3
# _qpack_xargus.py — Task-1 (notes/73 §8): extract x-argus from the REAL mssdk pcap.
# QPACK-decode the mssdk request HEADERS (dynamic-table refs resolved from the
# encoder stream), verify x-argus == 772 chars on the wire, then decode the
# structure [2B hdr][base64 1-pad] -> 578B = [2B hdr][576B ct] and AES-128-CBC
# decrypt with the app-constant x-argus key -> 576B pt with pt[0]=0xEC.
# Input = note-71 decrypted QUIC streams (ground-truth/getseed_wire/decoded/).
# Requires: pip install pylsqpack pycryptodome
import os, base64, binascii, sys
import pylsqpack
from Crypto.Cipher import AES

D = "ground-truth/getseed_wire/decoded"
H = "mssdk22-normal-alisg.tiktokv.com"
KEY = binascii.unhexlify("8252970d959b06db102e17d85c0ec1af")   # x-argus body key (app-const)
IV  = binascii.unhexlify("4d207ea37a419f7d622f81c6a2f53594")   # x-argus body IV  (app-const)

def rd(sid, d="C2S"):
    p = os.path.join(D, f"{H}_{d}_sid{sid}.bin")
    return open(p, "rb").read() if os.path.exists(p) else None

def rvarint(b, i):
    b0 = b[i]; ln = 1 << (b0 >> 6); v = b0 & 0x3f
    for k in range(1, ln): v = (v << 8) | b[i + k]
    return v, i + ln

def settings(ctl):
    i = 1; ftype, i = rvarint(ctl, i); flen, i = rvarint(ctl, i)
    end = i + flen; maxcap, blocked = 4096, 0
    while i < end:
        sid_, i = rvarint(ctl, i); val, i = rvarint(ctl, i)
        if sid_ == 1: maxcap = val
        if sid_ == 7: blocked = val
    return maxcap, blocked

def frames(s):
    i = 0
    while i < len(s):
        ft, i = rvarint(s, i); fl, i = rvarint(s, i)
        yield ft, s[i:i + fl]; i += fl

def main():
    maxcap, blocked = settings(rd(2))
    enc = rd(10); st, j = rvarint(enc, 0)          # strip encoder stream-type byte (0x02)
    dec = pylsqpack.Decoder(maxcap, blocked or 100)
    dec.feed_encoder(enc[j:])                       # populate dynamic table (x-argus lives here)
    ok = True
    for sid, ep in [(0, "get_seed"), (4, "dyn/task"), (8, "get_token")]:
        s = rd(sid)
        if not s: continue
        for ft, pl in frames(s):
            if ft != 1: continue
            _c, hdrs = dec.feed_header(sid, pl)
            xa = dict(hdrs).get(b"x-argus")
            if not xa: continue
            raw = base64.b64decode(xa)              # 772 chars -> 578B (1 trailing '=')
            ct = raw[2:]                            # [2B hdr][576B ct]
            pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)
            good = (len(xa) == 772 and len(ct) == 576 and pt[0] == 0xEC)
            ok &= good
            print("[%-9s] x-argus=%dchars hdr2=%s ct=%dB pt[0]=0x%02x nonce=%s  %s" % (
                ep, len(xa), raw[:2].hex(), len(ct), pt[0], pt[1:4].hex(),
                "OK" if good else "FAIL"))
    print("END-TO-END 772 VERIFY:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
