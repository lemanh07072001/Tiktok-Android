#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_inner_test.py — TEST QUYET DINH (offline, khong gui gi len server):

Gia thuyet: "inner VM-codec cua x-argus mssdk 772 thuc ra chinh la codec
Simon128/256 + reverse-XOR + framing 9/15 da giai o note 36/37 (chua ai test
tren pt mssdk)".

Du lieu: ENC_PT (plaintext tai AES-input, da decrypt AES) bat truc tiep tren
phone: cap.noindex/gettoken_crypt/crypt_20260905_151444.jsonl

Codec tham chieu (DA VERIFY round-trep tren capture that): xargus_decode.py +
_f24_xargus.py (port self-contained). Inner algo:
    rb23  = PT[-15:-13]; rb = rb01 + rb23            (rb01 = 2B ngoai phong)
    region= PT[9:-15]; simct = region[::-1]; xa=simct[:8]
    simct[i>=8] ^= xa[i%4]; simct = simct[8:]
    kl   = unpack("<QQQQ", SM3(session_psk + rb + session_psk)[:32])
    report = Simon128/256-ECB-decode(simct, kl)      # 08 d2 a4 80 82 04 ...

Vi rb01 khong co trong capture (no nam ngoai AES payload) -> brute 65536 gia tri.
Check HIT: 6 byte dau report == 08 d2 a4 80 82 04 (tham chieu offline_inner_report.hex).
"""
import sys, os, json, time, base64, struct, random, multiprocessing as mp

BASE     = r"D:\Tiktok-Android"
CAPFILE  = os.path.join(BASE, r"cap.noindex\gettoken_crypt\crypt_20260905_151444.jsonl")
DS_DIR   = os.path.join(BASE, r"huongB_devirt19\cap.noindex\device_secret")
SYNCFILE = os.path.join(BASE, r"ground-truth\sync_capture.json")
RESULT   = os.path.join(BASE, r"huongB_devirt19\_inner_test_result.txt")

MAGIC6  = bytes.fromhex("08d2a4808204")     # head cua report genuine (offline_inner_report.hex)
TGT48   = int.from_bytes(MAGIC6, "little")  # low-48 bit cua tu a sau decode
ARGUS_MAGIC = 0x20200929
M64 = (1 << 64) - 1
SIGN_KEY = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")

# ============================================================================
# SM3 thuan Python (tuan chuan GM/T 0004-2012) — self-test vs gmssl
# ============================================================================
_SM3_IV = [0x73801668 ^ 0x07,  # 0x7380166f
           0x4914B2B9, 0x172442D7, 0xDA8A0600,
           0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
_M32 = 0xFFFFFFFF

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32

def sm3_compress(V, block):
    W = list(struct.unpack(">16I", block))
    for j in range(16, 68):
        x = W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)
        x = x ^ _rotl(x, 15) ^ _rotl(x, 23)
        W.append(x ^ _rotl(W[j-13], 7) ^ W[j-6])
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79CC4519 if j < 16 else 0x7A879D8A
        if j < 16:
            ff = A ^ B ^ C
            gg = E ^ F ^ G
        else:
            ff = (A & B) | (A & C) | (B & C)
            gg = (E & F) | ((E ^ _M32) & G)
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(T, j % 32)) & _M32, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (ff + D + SS2 + (W[j] ^ W[j+4])) & _M32  # W'[j] = W[j] ^ W[j+4] (GM/T 0004-2012)
        TT2 = (gg + H + SS1 + W[j]) & _M32
        D = C
        C = _rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = TT2 ^ _rotl(TT2, 9) ^ _rotl(TT2, 17)
    return [(a ^ v) & _M32 for a, v in zip((A, B, C, D, E, F, G, H), V)]

def sm3(msg):
    V = list(_SM3_IV)
    ml = len(msg) * 8
    pad = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack(">Q", ml)
    for i in range(0, len(pad), 64):
        V = sm3_compress(V, pad[i:i+64])
    return struct.pack(">8I", *V)

# ============================================================================
# Simon128/256 — PORT VERBATIM tu _f24_xargus.py (da verify tren capture that)
# ============================================================================
rol64 = lambda x, n: ((x << n) | (x >> (64 - n))) & M64
ror64 = lambda x, n: ((x >> n) | (x << (64 - n))) & M64

Z = {
 0: "11111010001001010110000111001101111101000100101011000011100110",
 1: "10001110111110010011000010110101000111011111001001100001011010",
 2: "10101111011100000011010010011000101000010001111110010110110011",
 3: "11011011101011000110010111100000010010001010011100110100001111",
 4: "11010001111001101011011000100000010111000011001010010011101111",
}

def simon_key_expansion(kl, zj=4, zrev=False):
    zstr = Z[zj][::-1] if zrev else Z[zj]
    rk = list(kl)
    for i in range(4, 72):
        tmp = ror64(rk[i-1], 3) ^ rk[i-3]
        tmp ^= ror64(tmp, 1)
        rk.append(((~rk[i-4]) & M64) ^ tmp ^ int(zstr[(i-4) % 62]) ^ 3)
    return rk

def simon_dec_block(a, b, rk):
    for i in range(71, -1, -1):
        fa = (rol64(a, 1) & rol64(a, 8)) ^ rol64(a, 2)
        a, b = (b ^ fa ^ rk[i]) & M64, a
    return a, b

def simon_enc_block(a, b, rk):
    # nghich dao cua dec (de self-test round-trip + vector)
    for i in range(0, 72):
        fb = (rol64(b, 1) & rol64(b, 8)) ^ rol64(b, 2)
        a, b = b, (a ^ fb ^ rk[i]) & M64
    return a, b

# ---- ban nhanh (dung trong brute) — PHAI bit-exact voi ban tren ----
def zbits_of(zj, zrev):
    s = Z[zj][::-1] if zrev else Z[zj]
    b = [int(c) for c in s]
    return [b[k % 62] for k in range(68)]  # mo rang theo vong (i-4)%62 nhu ban tham chieu

def fast_key_expansion(kl, zbits):
    rk = list(kl)
    ap = rk.append
    for i in range(4, 72):
        t = ror64(rk[i-1], 3) ^ rk[i-3]
        t ^= ((t >> 1) | (t << 63)) & M64
        ap(((~rk[i-4]) & M64) ^ t ^ zbits[i-4] ^ 3)
    return rk

def fast_dec_block(a, b, rk):
    for i in range(71, -1, -1):
        a1 = ((a << 1) | (a >> 63)) & M64
        a8 = ((a << 8) | (a >> 56)) & M64
        a2 = ((a << 2) | (a >> 62)) & M64
        a, b = (b ^ ((a1 & a8) ^ a2) ^ rk[i]) & M64, a
    return a, b

# ============================================================================
# Framing (verbatim xargus_decode.py) + cac bien the fallback
# ============================================================================
def make_simct(pt, hdr, tail, mode, cut=None, off=0):
    """mode: 'revxor' (chinh), 'plain' (khong reverse-xor), 'nofrm' (simct=pt[off:])"""
    L = len(pt)
    if mode == "nofrm":
        return pt[off:]
    region = pt[hdr:L - tail]
    if mode == "revxor":
        if len(region) < 8:
            return None
        xored = region[::-1]
        xa = xored[:8]
        p = bytearray(xored)
        for i in range(8, len(p)):
            p[i] ^= xa[i % 4]
        return bytes(p[8:])
    if mode == "plain":
        if cut == "head8":
            return bytes(region[8:])
        if cut == "tail8":
            return bytes(region[:-8])
        return bytes(region)
    raise ValueError(mode)

def rb23_of(pt, tail):
    return pt[-tail:-tail + 2]

def check_magic(rep):
    if not rep or rep[0] != 0x08:
        return None
    v = s = 0
    i = 1
    while i < len(rep) and i < 11:
        c = rep[i]; v |= (c & 0x7f) << s; i += 1; s += 7
        if not c & 0x80:
            break
    return v if v == (ARGUS_MAGIC << 1) else None

def full_decode(pt, rb01bytes, psk, hdr, tail, mode, cut, off, zj, zrev):
    simct = make_simct(pt, hdr, tail, mode, cut, off)
    if simct is None or len(simct) % 16:
        return None
    rb = rb01bytes + rb23_of(pt, tail)
    kl = list(struct.unpack("<QQQQ", sm3(psk + rb + psk)[:32]))
    rk = simon_key_expansion(kl, zj, zrev)
    out = bytearray()
    for i in range(0, len(simct), 16):
        a, b = struct.unpack("<QQ", simct[i:i+16])
        a, b = simon_dec_block(a, b, rk)
        out += struct.pack("<QQ", a, b)
    return bytes(out)

def walk_fields(rep):
    out, i = {}, 0
    while i < len(rep):
        if rep[i] == 0:
            break
        tag = s = 0; j = i
        while True:
            c = rep[j]; tag |= (c & 0x7f) << s; j += 1; s += 7
            if not c & 0x80:
                break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v = s2 = 0
            while True:
                c = rep[j]; v |= (c & 0x7f) << s2; j += 1; s2 += 7
                if not c & 0x80:
                    break
            out.setdefault(fn, []).append(v)
        elif wt == 2:
            l = s2 = 0
            while True:
                c = rep[j]; l |= (c & 0x7f) << s2; j += 1; s2 += 7
                if not c & 0x80:
                    break
            out.setdefault(fn, []).append(rep[j:j+l]); j += l
        elif wt == 1:
            out.setdefault(fn, []).append(rep[j:j+8]); j += 8
        elif wt == 5:
            out.setdefault(fn, []).append(rep[j:j+4]); j += 4
        else:
            break
        i = j
    return out

# ============================================================================
# WORKER: brute rb01 0..65535 tren block dau, check 6-byte magic
# ============================================================================
_DG = {}  # (rb23hex, pskhex) -> list 65536 digest, index n = rb01 BE (n>>8, n&0xff)

def get_digests(rb23, psk):
    """digest[n] = SM3(psk + bytes((n>>8, n&0xff)) + rb23 + psk).
    Tap digest cho LE(rb01) trung tap BE — chi khac thu tu (hoan vi byte n)."""
    key = (rb23.hex(), psk.hex())
    d = _DG.get(key)
    if d is None:
        d = []
        blk1 = bytearray(psk + b"\x00\x00" + rb23 + psk[:28])          # 64B, chi 2 byte [32:34] bien
        blk2 = psk[28:] + b"\x80" + b"\x00" * 51 + struct.pack(">Q", 68 * 8)  # hang (msg=68B)
        V0 = list(_SM3_IV)
        for n in range(65536):
            blk1[32] = (n >> 8) & 0xFF
            blk1[33] = n & 0xFF
            V = sm3_compress(V0, bytes(blk1))
            V = sm3_compress(V, blk2)
            d.append(struct.pack(">8I", *V))
        _DG[key] = d
    return d

def brute_job(j):
    """1 job = 1 pt x 1 psk x 1 framing x 1 z-config: brute 65536 rb01 ca BE va LE."""
    t0 = time.time()
    try:
        pt = bytes.fromhex(j["pt_hex"])
        simct = make_simct(pt, j["hdr"], j["tail"], j["mode"], j.get("cut"), j.get("off", 0))
        if simct is None or len(simct) % 16 or len(simct) <= 0:
            return dict(status="MISALIGN", alen=(len(simct) if simct is not None else -1), **{k: j[k] for k in j if k != "pt_hex"})
        psk = bytes.fromhex(j["psk_hex"])
        rb23 = bytes.fromhex(j["rb23_hex"])
        a0, b0 = struct.unpack("<QQ", simct[:16])
        digests = get_digests(rb23, psk)
        zbits = zbits_of(j["zj"], j["zrev"])
        fk, fd = fast_key_expansion, fast_dec_block
        hits = []  # (endian, n)
        for n in range(65536):                     # BE: rb01 = (n>>8, n&0xff)
            kl = struct.unpack("<QQQQ", digests[n])
            rk = fk(list(kl), zbits)
            a, b = fd(a0, b0, rk)
            if (a & 0xFFFFFFFFFFFF) == TGT48:
                hits.append(("be", n))
        for n in range(65536):                     # LE: rb01 = (n&0xff, n>>8) -> digest index hoan vi
            m = ((n & 0xFF) << 8) | (n >> 8)
            kl = struct.unpack("<QQQQ", digests[m])
            rk = fk(list(kl), zbits)
            a, b = fd(a0, b0, rk)
            if (a & 0xFFFFFFFFFFFF) == TGT48:
                hits.append(("le", n))
        res = {k: v for k, v in j.items() if k != "pt_hex"}
        res["status"] = "MISS" if not hits else "HIT"
        res["tried"] = 2 * 65536
        res["secs"] = round(time.time() - t0, 1)
        if hits:
            det = []
            for endian, n in hits:
                rb01 = bytes((n >> 8, n & 0xFF)) if endian == "be" else bytes((n & 0xFF, n >> 8))
                rep = full_decode(pt, rb01, psk, j["hdr"], j["tail"], j["mode"], j.get("cut"), j.get("off", 0), j["zj"], j["zrev"])
                if rep is None:
                    det.append((endian, n, None, None, None, 0))
                    continue
                asc = "".join(chr(c) if 32 <= c < 127 else "." for c in rep[:64])
                det.append((endian, n, rep.hex(), check_magic(rep), asc, len(rep)))
            res["hits"] = det
        return res
    except Exception as e:
        import traceback
        return dict(status="ERROR", err=repr(e), tb=traceback.format_exc()[-800:],
                    **{k: j[k] for k in j if k != "pt_hex"})

# ============================================================================
# PARENT: parse, psk, jobs, self-tests
# ============================================================================
def parse_pts():
    pts, skipped = [], []
    for line in open(CAPFILE, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("k") != "ENC_PT":
            continue
        try:
            pt = bytes.fromhex(e["pt"])
        except Exception:
            skipped.append((e.get("i"), e.get("len"), "badhex"))
            continue
        if pt and pt[0] == 0xEC and len(pt) % 16 == 0:
            pts.append((e.get("i"), len(pt), pt))
        else:
            skipped.append((e.get("i"), e.get("len"), "first=%s mod16=%d" % (pt[:1].hex(), len(pt) % 16)))
    return pts, skipped

def load_psks():
    cands = [("SIGN_KEY", SIGN_KEY)]
    notes = []
    try:
        for fn in sorted(os.listdir(DS_DIR)):
            if not fn.endswith(".json"):
                continue
            j = json.load(open(os.path.join(DS_DIR, fn), encoding="utf-8"))
            for k, v in j.items():
                if not isinstance(v, str):
                    continue
                # dyn_seed: b64
                if k == "dyn_seed":
                    try:
                        b = base64.b64decode(v)
                        notes.append("dyn_seed b64 -> %dB" % len(b))
                        for s in range(0, len(b) - 31, 32):
                            cands.append(("dyn_seed[%d:%d]" % (s, s + 32), b[s:s + 32]))
                    except Exception as e:
                        notes.append("dyn_seed err %r" % e)
                    continue
                # hex 32B/48B
                hv = v.replace("-", "")
                if len(hv) >= 56 and all(ch in "0123456789abcdefABCDEF" for ch in hv) and len(hv) % 2 == 0:
                    try:
                        b = bytes.fromhex(hv)
                    except Exception:
                        continue
                    if len(b) == 32:
                        cands.append(("%s.%s" % (fn[:6], k), b))
                        notes.append("%s = 32B hex -> candidate" % k)
                    elif len(b) == 48:
                        cands.append(("%s.%s[:32]" % (fn[:6], k), b[:32]))
                        cands.append(("%s.%s[16:48]" % (fn[:6], k), b[16:48]))
                        notes.append("%s = 48B hex -> 2 candidates" % k)
                    else:
                        notes.append("%s = hex %dB -> SKIP (khong phai 32/48B)" % (k, len(b)))
                else:
                    notes.append("%s = str len %d -> SKIP" % (k, len(v)))
    except Exception as e:
        notes.append("ds dir err %r" % e)
    return cands, notes

def selftest():
    lines = []
    P = lines.append
    P("=" * 72)
    P("SELF-TESTS")
    # 1) SM3 vs gmssl + vector
    ok = True
    try:
        from gmssl import sm3 as gsm3
        rnd = random.Random(20260905)
        for L in [0, 1, 31, 32, 33, 55, 63, 64, 65, 67, 68, 69, 100, 127, 128, 200]:
            m = bytes(rnd.randrange(256) for _ in range(L))
            a = sm3(m).hex()
            b = gsm3.sm3_hash(list(m))
            if a != b:
                ok = False
                P("  SM3 MISMATCH len=%d my=%s gm=%s" % (L, a, b))
        abc = sm3(b"abc").hex()
        P("  sm3('abc') = %s  (expect 66c7f0f4...b4ba8e0)  %s" % (abc, "OK" if abc == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" else "FAIL"))
    except ImportError:
        ok = False
        P("  gmssl KHONG import duoc — chi co vector 'abc'")
        abc = sm3(b"abc").hex()
        ok = abc == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        P("  sm3('abc') = %s  %s" % (abc, "OK" if ok else "FAIL"))
    P("  SM3 self-test: %s" % ("PASS" if ok else "FAIL"))
    sm3_ok = ok

    # 2) Simon round-trip + fast==reference + official vector
    rnd = random.Random(3637)
    ok2 = True
    for _ in range(50):
        kl = [rnd.getrandbits(64) for _ in range(4)]
        a, b = rnd.getrandbits(64), rnd.getrandbits(64)
        rk = simon_key_expansion(kl)
        if simon_key_expansion(kl) != fast_key_expansion(kl, zbits_of(4, False)):
            ok2 = False; P("  fast_key_expansion != reference"); break
        ea, eb = simon_enc_block(a, b, rk)
        da, db = simon_dec_block(ea, eb, rk)
        if (da, db) != (a, b):
            ok2 = False; P("  round-trip FAIL"); break
        if fast_dec_block(a, b, rk) != simon_dec_block(a, b, rk):
            ok2 = False; P("  fast_dec_block != reference"); break
    P("  Simon enc/dec round-trip + fast==ref: %s" % ("PASS" if ok2 else "FAIL"))
    simon_rt = ok2

    # official vector Simon128/256 (implementation guide):
    key = bytes(range(32))
    ptx = bytes.fromhex("74206e69206d6f6f6d69732061207369")
    ctx = bytes.fromhex("8d2b5579afc8a3a0bf558f33d5fa5907")
    matched = None
    for pt_order in ("x_first", "y_first"):
        for ko in ("fwd", "rev"):
            for ct_order in ("xy", "yx"):
                for zrev in (False, True):
                    kl = [int.from_bytes(key[8*i:8*i+8], "big") for i in range(4)]
                    if ko == "rev":
                        kl = kl[::-1]
                    rk = simon_key_expansion(kl, 4, zrev)
                    if pt_order == "x_first":   # guide-x (=xargus b) = tu thu nhat cua pt
                        a0, b0 = int.from_bytes(ptx[8:], "big"), int.from_bytes(ptx[:8], "big")
                    else:
                        a0, b0 = int.from_bytes(ptx[:8], "big"), int.from_bytes(ptx[8:], "big")
                    ea, eb = simon_enc_block(a0, b0, rk)
                    ct = struct.pack(">QQ", eb, ea) if ct_order == "xy" else struct.pack(">QQ", ea, eb)
                    if ct == ctx:
                        matched = (pt_order, ko, ct_order, zrev)
    P("  Official vector Simon128/256: %s" % ("MATCH %s" % (matched,) if matched else "NO-MATCH trong 16 config convention (khong chan test chinh)"))

    # 3) end-to-end: decode X-Argus that (sync_capture.json, bootstrap SIGN_KEY)
    e2e = "SKIPPED"
    try:
        from Crypto.Cipher import AES
        j = json.load(open(SYNCFILE, encoding="utf-8"))
        raw = base64.b64decode(j["X-Argus"])
        aes_key = __import__("hashlib").md5(SIGN_KEY[:16]).digest()
        aes_iv = __import__("hashlib").md5(SIGN_KEY[16:]).digest()
        pt = AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(raw[2:])
        rep = full_decode(pt, raw[:2], SIGN_KEY, 9, 15, "revxor", None, 0, 4, False)
        m = check_magic(rep) if rep else None
        # cross-check voi ban _f24_xargus doc lap (gmssl + Simon rieng)
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import _f24_xargus
            rep2 = _f24_xargus.decode_xargus(j["X-Argus"], SIGN_KEY)
            same = (rep == rep2)
        except Exception as ce:
            same = None
            P("  (_f24 cross-check err %r)" % ce)
        if m == (ARGUS_MAGIC << 1):
            e2e = "PASS (magic=%s, report len=%d, head=%s, byte-eq _f24: %s)" % (m, len(rep), rep[:16].hex(), same)
        else:
            e2e = "FAIL (magic=%s, report len=%d, head=%s, byte-eq _f24: %s)" % (m, len(rep) if rep else 0, rep[:16].hex() if rep else "-", same)
    except Exception as e:
        e2e = "ERROR %r" % e
    P("  End-to-end sync_capture.json (codec note-36/37 vs x-argus that): %s" % e2e)
    P("=" * 72)
    return lines, sm3_ok, simon_rt, e2e

def variant_label(j):
    if j["mode"] == "nofrm":
        return "nofrm off=%d" % j["off"]
    lab = "%d/%d %s" % (j["hdr"], j["tail"], j["mode"])
    if j["mode"] == "plain" and j.get("cut"):
        lab += "+%s" % j["cut"]
    return lab

def main():
    selftest_only = "--selftest" in sys.argv
    quick = "--quick" in sys.argv
    out = open(RESULT, "w", encoding="utf-8")
    def W(s=""):
        print(s, flush=True)
        out.write(s + "\n")
        out.flush()

    W("_inner_test.py — test quy dinh: codec Simon note-36/37 co giai duoc inner pt mssdk?")
    W("capture: %s" % CAPFILE)
    W("time: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    W("")

    # ---- self-tests ----
    lines, sm3_ok, simon_rt, e2e = selftest()
    for l in lines:
        W(l)
    W("")
    if not (sm3_ok and simon_rt):
        W("SELF-TEST FAIL -> DUNG (so lieu brute se vo nghia).")
        return
    if not e2e.startswith("PASS"):
        W("CANH BAO: end-to-end sync_capture khong PASS (%s) -> codec port co the lech." % e2e)
    if selftest_only:
        return

    # ---- parse ----
    pts, skipped = parse_pts()
    lens = {}
    for _, L, _ in pts:
        lens[L] = lens.get(L, 0) + 1
    W("1) PARSE ENC_PT: giu %d pt (pt[0]==0xEC & len%%16==0); bo %d: %s" % (len(pts), len(skipped), skipped))
    W("   phan bo len: %s" % dict(sorted(lens.items())))
    rb23s = {}
    for i, L, p in pts:
        rb23s[p[-15:-13].hex()] = rb23s.get(p[-15:-13].hex(), 0) + 1
    W("   rb23 (=pt[-15:-13]) distinct: %s" % rb23s)
    W("")

    # ---- psk ----
    psks, pnotes = load_psks()
    W("2) SESSION_PSK candidates (%d):" % len(psks))
    for n, b in psks:
        W("   %-24s %s" % (n, b.hex()))
    for n in pnotes:
        W("   [note] %s" % n)
    W("")

    first10 = pts[:10]
    allpts = pts if not quick else first10

    # ---- build job list ----
    jobs = []
    def add(pt_list, psk_list, hdr, tail, mode, cut=None, off=0, zj=4, zrev=False, stage=""):
        for i, L, p in pt_list:
            simct_len = (L - off) if mode == "nofrm" else (L - hdr - tail - (8 if (mode == "revxor" or cut in ("head8", "tail8")) else 0))
            for pname, pb in psk_list:
                jobs.append(dict(stage=stage, pi=i, ilen=L, hdr=hdr, tail=tail, mode=mode,
                                 cut=cut, off=off, zj=zj, zrev=zrev,
                                 psk_name=pname, psk_hex=pb.hex(),
                                 pt_hex=p.hex(), rb23_hex=(p[-tail:-tail+2] if mode != "nofrm" else p[-15:-13]).hex(),
                                 simct_len=simct_len))

    # (misalign se duoc parent check cong thuc; chi dispatch job thuc su aligned)
    dispatched = []
    misaligned = []

    def add_variant(pt_list, psk_list, hdr, tail, mode, cut=None, off=0, zj=4, zrev=False, stage=""):
        # cong thuc do dai (phai khop make_simct)
        L0 = pt_list[0][1]
        if mode == "nofrm":
            alen = L0 - off
        else:
            base = L0 - hdr - tail
            if mode == "revxor" or cut in ("head8", "tail8"):
                alen = base - 8
            else:
                alen = base
        if alen % 16 or alen <= 0:
            lab = "%d/%d %s" % (hdr, tail, mode)
            if mode == "nofrm":
                lab += " off=%d" % off
            elif cut:
                lab += "+%s" % cut
            misaligned.append(dict(stage=stage, hdr=hdr, tail=tail, mode=mode, cut=cut, off=off,
                                   label=lab, alen=alen, pts=len(pt_list)))
            return
        before = len(jobs)
        add(pt_list, psk_list, hdr, tail, mode, cut, off, zj, zrev, stage)
        dispatched.extend(jobs[before:])

    sign_only = [p for p in psks if p[0] == "SIGN_KEY"]

    # STAGE 1: framing chinh 9/15 revxor, SIGN_KEY, moi pt, 2 endian
    add_variant(allpts, sign_only, 9, 15, "revxor", stage="S1-main-SIGN_KEY")
    # STAGE 2: framing chinh, cac psk device-secret
    for pname, pb in psks:
        if pname == "SIGN_KEY":
            continue
        add_variant(allpts, [(pname, pb)], 9, 15, "revxor", stage="S2-main-%s" % pname)
    # STAGE 3: z-variants (SIGN_KEY, 10 pt dau)
    for zj, zrev in [(3, False), (4, True), (3, True)]:
        add_variant(first10, sign_only, 9, 15, "revxor", zj=zj, zrev=zrev, stage="S3-z%d%s" % (zj, "rev" if zrev else ""))
    # STAGE 4: fallback framings (10 pt dau, TAT CA psk)
    add_variant(first10, psks, 9, 15, "plain", cut="head8", stage="S4-plain9/15+head8")
    add_variant(first10, psks, 9, 15, "plain", cut="tail8", stage="S4-plain9/15+tail8")
    for off in (0, 16, 32):
        add_variant(first10, psks, 15, 15, "nofrm", off=off, stage="S4-nofrm off=%d" % off)
    # grid misalign (bao cao, khong dispatch)
    for hdr in (4, 9, 13):
        for tail in (13, 15, 16):
            if (hdr, tail) == (9, 15):
                continue
            add_variant(first10, psks, hdr, tail, "revxor", stage="S4-grid")
            add_variant(first10, psks, hdr, tail, "plain", stage="S4-grid")
    add_variant(first10, psks, 15, 15, "nofrm", off=4, stage="S4-nofrm off=4")
    add_variant(first10, psks, 15, 15, "nofrm", off=8, stage="S4-nofrm off=8")

    W("3) KE HOACH TEST:")
    W("   dispatch %d job brute (moi job = 65536 rb01 x SM3+keyexp+1 block Simon)" % len(dispatched))
    W("   misaligned (bo vi do lech 16B, KHONG brute): %d bien the:" % len(misaligned))
    for m in misaligned:
        W("     %-28s alen=%d (%%16=%d)" % (m["label"], m["alen"], m["alen"] % 16))
    W("")

    # ---- run ----
    W("4) BRUTE:")
    nproc = min(32, mp.cpu_count())
    W("   workers = %d" % nproc)
    t00 = time.time()
    results = []
    completed = 0
    SOFT_CAP = 3600  # giay
    try:
        with mp.Pool(nproc) as pool:
            for res in pool.imap_unordered(brute_job, dispatched, chunksize=1):
                completed += 1
                results.append(res)
                if res["status"] == "HIT":
                    W("   [HIT] pt#%s L=%s %s psk=%s z=%d/%d hits=%d" % (
                        res["pi"], res["ilen"], variant_label(res), res["psk_name"],
                        res["zj"], int(res["zrev"]), len(res.get("hits", []))))
                    for (endian, n, rephex, m, asc, rlen) in res["hits"]:
                        W("        endian=%s rb01=%04X  report len=%d magic=%s" % (endian, n, rlen, m))
                        W("        head64=%s" % ((rephex or "")[:128]))
                        W("        ascii =%s" % asc)
                elif res["status"] == "ERROR":
                    W("   [ERR ] pt#%s %s %s: %s" % (res["pi"], variant_label(res), res.get("psk_name"), res.get("err")))
                else:
                    if completed % 50 == 0 or completed <= 5:
                        W("   [%4d/%d] pt#%s L=%s %s psk=%s -> %s (%ds, tong %ds)" % (
                            completed, len(dispatched), res["pi"], res["ilen"], variant_label(res),
                            res["psk_name"], res["status"], res.get("secs", -1), int(time.time() - t00)))
                if time.time() - t00 > SOFT_CAP:
                    W("   !! vuot soft-cap %ds -> dung dispatch, ghi nhan phan da chay" % SOFT_CAP)
                    pool.terminate()
                    break
    except Exception as e:
        W("   pool error: %r" % e)

    # ---- summary ----
    W("")
    W("5) TONG KET:")
    hits = [r for r in results if r["status"] == "HIT"]
    pt_total = len(allpts)
    pt_hit = sorted({r["pi"] for r in hits})
    W("   dispatch=%d  completed=%d  HIT=%d  ERROR=%d" % (len(dispatched), completed, len(hits), sum(1 for r in results if r["status"] == "ERROR")))
    W("   so pt giai duoc protobuf magic (6-byte 08d2a4808204): %d / %d%s" % (
        len(pt_hit), pt_total, ("  (pt#: %s)" % pt_hit) if pt_hit else ""))
    if hits:
        W("   cac to hop TRUNG:")
        seen = set()
        for r in hits:
            k = (r["hdr"], r["tail"], r["mode"], r.get("cut"), r.get("off"), r["psk_name"], r["zj"], r["zrev"])
            if k in seen:
                continue
            seen.add(k)
            ends = ",".join(sorted({h[0] for h in r.get("hits", [])}))
            W("     %s psk=%s endian=%s z=%d/%d" % (variant_label(r), r["psk_name"], ends, r["zj"], int(r["zrev"])))
    else:
        W("   0 HIT. DA THU (moi to hop = brute du 65536 rb01 ca 2 endian BE+LE):")
        W("     framing chinh 9/15 revxor: %d psk x 2 endian = %d to hop" % (len(psks), len(psks) * 2))
        W("     z-variants (SIGN_KEY): (3,False),(4,True),(3,True) x 2 endian")
        W("     fallback aligned: plain9/15+head8, plain9/15+tail8, nofrm off 0/16/32 — moi cai x %d psk x 2 endian" % len(psks))
        W("     fallback misaligned (da kiem, bo): %s" % ", ".join(sorted({m["label"] for m in misaligned})))
        W("   => codec Simon note-36/37 KHONG giai duoc bat ky pt nao trong cac to hop da thu.")
    W("   thoi luong: %d giay" % int(time.time() - t00))
    W("   (khong ket luan solved/wall — chi so lieu)")
    out.close()

if __name__ == "__main__":
    main()
