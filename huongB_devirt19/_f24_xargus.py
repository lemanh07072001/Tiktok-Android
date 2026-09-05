#!/usr/bin/env python3
# _f24_xargus.py — port xargus_decode.py (Simon128/256 tu implement, xac nhan bang ARGUS magic)
# + boc field #24 (dyn_seed) va field #5 (device_id) tu moi capture genuine.
import sys, os, json, base64, hashlib, struct, re, glob
from Crypto.Cipher import AES

def sm3_py(b):
    # dung gmssl
    from gmssl import sm3 as _s
    return bytes.fromhex(_s.sm3_hash(list(b)))

M64 = (1 << 64) - 1
rol64 = lambda x, n: ((x << n) | (x >> (64 - n))) & M64
ror64 = lambda x, n: ((x >> n) | (x << (64 - n))) & M64
Z = {
 0: "11111010001001010110000111001101111101000100101011000011100110",
 1: "10001110111110010011000010110101000111011111001001100001011010",
 2: "10101111011100000011010010011000101000010001111110010110110011",
 3: "11011011101011000110010111100000010010001010011100110100001111",
 4: "11010001111001101011011000100000010111000011001010010011101111",
}
C64 = M64 - 3  # 2^64 - 4

def simon_key_expansion(kl, zj=4, zrev=False):
    zstr = Z[zj][::-1] if zrev else Z[zj]
    rk = list(kl)
    for i in range(4, 72):
        tmp = ror64(rk[i - 1], 3) ^ rk[i - 3]
        tmp ^= ror64(tmp, 1)
        rk.append(((~rk[i - 4]) & M64) ^ tmp ^ (int(zstr[(i - 4) % 62])) ^ 3)
    return rk

def simon_dec_block(a, b, rk):
    for i in range(71, -1, -1):
        fa = (rol64(a, 1) & rol64(a, 8)) ^ rol64(a, 2)
        a, b = (b ^ fa ^ rk[i]) & M64, a
    return a, b

SIGN_KEY = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
AES_KEY = hashlib.md5(SIGN_KEY[:16]).digest()
AES_IV = hashlib.md5(SIGN_KEY[16:]).digest()
HDR, TAIL = 9, 15
ARGUS_MAGIC = 0x20200929

def decode_xargus(xa_b64, session_psk=SIGN_KEY, zj=4, zrev=False):
    raw = base64.b64decode(xa_b64)
    rb01, ct = raw[:2], raw[2:]
    pt = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ct)
    rb = rb01 + pt[-TAIL:-TAIL + 2]
    region = pt[HDR:len(pt) - TAIL]
    xored = region[::-1]
    xa = xored[:8]
    p = bytearray(xored)
    for i in range(8, len(p)):
        p[i] ^= xa[i % 4]
    simct = bytes(p[8:])
    assert len(simct) % 16 == 0, "simon not 16-aligned: %d" % len(simct)
    kdig = sm3_py(session_psk + rb + session_psk)[:32]
    kl = list(struct.unpack("<QQQQ", kdig))
    rk = simon_key_expansion(kl, zj, zrev)
    out = bytearray()
    for i in range(0, len(simct), 16):
        a, b = struct.unpack("<QQ", simct[i:i + 16])
        a, b = simon_dec_block(a, b, rk)
        out += struct.pack("<QQ", a, b)
    return bytes(out)

def check_magic(rep):
    if not rep or rep[0] != 0x08: return None
    v = s = 0; i = 1
    while i < len(rep) and i < 11:
        c = rep[i]; v |= (c & 0x7f) << s; i += 1; s += 7
        if not c & 0x80: break
    return v if v == (ARGUS_MAGIC << 1) else None

def walk_fields(rep):
    """tra ve dict field -> list bytes/int (top level, bo qua nested)"""
    out, i = {}, 0
    while i < len(rep):
        if rep[i] == 0: break  # padding 00
        tag = s = 0; j = i
        while True:
            c = rep[j]; tag |= (c & 0x7f) << s; j += 1; s += 7
            if not c & 0x80: break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v = s2 = 0
            while True:
                c = rep[j]; v |= (c & 0x7f) << s2; j += 1; s2 += 7
                if not c & 0x80: break
            out.setdefault(fn, []).append(v)
        elif wt == 2:
            l = s2 = 0
            while True:
                c = rep[j]; l |= (c & 0x7f) << s2; j += 1; s2 += 7
                if not c & 0x80: break
            out.setdefault(fn, []).append(rep[j:j + l]); j += l
        elif wt == 1: out.setdefault(fn, []).append(rep[j:j + 8]); j += 8
        elif wt == 5: out.setdefault(fn, []).append(rep[j:j + 4]); j += 4
        else: break  # wt 3/4/6/7 = padding/rac duoi report
        i = j
    return out

def main():
    caps = []
    # sync_capture.json
    try:
        j = json.load(open("ground-truth/sync_capture.json"))
        caps.append(("sync_capture", j["X-Argus"]))
    except Exception as e: print("sync err", e)
    # realsign_capture.json hdr
    try:
        j = json.load(open("ground-truth/realsign_capture.json"))
        m = re.search(r"[A-Za-z0-9+/=]{300,}", j["hdr"])
        if m: caps.append(("realsign_capture", m.group()))
    except Exception as e: print("realsign err", e)
    # quet them cac file khac
    for f in glob.glob("ground-truth/*.txt") + glob.glob("ground-truth/*.json"):
        try: t = open(f, encoding="utf8", errors="ignore").read()
        except Exception: continue
        for m in re.finditer(r"[A-Za-z0-9+/=]{700,}", t):
            v = m.group()
            if len(v) % 4 == 0 and (f, v) not in [(a, b) for a, b in caps]:
                caps.append((os.path.basename(f), v))
    seen = set()
    for name, xa in caps:
        if xa in seen: continue
        seen.add(xa)
        ok = None
        for zj, zrev in [(4, False), (4, True), (3, False), (2, False), (1, False), (0, False)]:
            try: rep = decode_xargus(xa, zj=zj, zrev=zrev)
            except Exception: continue
            ok = check_magic(rep)
            if ok: break
        if not ok:
            print(f"[{name}] len={len(xa)} MAGIC FAIL (all z variants)"); continue
        f = walk_fields(rep)
        print(f"[{name}] len={len(xa)} magic OK — fields: {sorted(f.keys())}")
        if 5 in f: print("   #5 device_id =", f[5][0].decode("latin1", "replace"))
        if 24 in f:
            v = f[24][0]
            print("   #24 =", v.decode("latin1", "replace"))
            print("   #24 len =", len(v))
        if 7 in f: print("   #7 appver =", f[7][0])
        others = {k: (len(v[0]) if isinstance(v[0], bytes) else v[0]) for k, v in f.items() if k not in (5, 24, 7)}
        print("   others:", others)

if __name__ == "__main__":
    main()
