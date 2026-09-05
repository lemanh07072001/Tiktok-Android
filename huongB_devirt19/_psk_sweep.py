#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_psk_sweep.py — TEST OFFLINE gia thuyet "rotated SESSION_PSK" cho 19 mau MISS
(idx 81..99, L in {592,608}) cua capture ENC_PT mssdk.

THUAN OFFLINE — khong gui gi len mang. KHONG in gia tri psk/secret ra
stdout/log/file — chi LABEL ung viên + HIT/MISS + field-SET (so field).

Codec: TAI SU DUNG Y NGUYEN _inner_test.py (da verify):
    rb23 = pt[-15:-13]; rb = rb01(2B brute) + rb23
    kl   = SM3(psk + rb + psk)[:32] -> Simon128/256 z4 ECB-decode(simct revxor 9/15)
    HIT  = report[:6] == 08d2a4808204
Chi THAY psk (SESSION_PSK ung vien) va brute rb01 0..65535.

Luu y bruteforce: rb01 = (n>>8, n&0xff) voi n = 0..65535 da BAO TRON ca 65536
gia tri 2-byte co the (pass LE trong _inner_test la tap trung lap — chinh comment
do ghi "tap digest cho LE(rb01) trung tap BE"). Neu HIT thi confirm bang
full_decode + report[:6] == magic.

digest_sweep (cache 65536 SM3 digest / (psk,rb23)) la ban TONG QUAT hoa cua
get_digests cua _inner_test (ban goc chi dung cho psk dung 32B; ung vien o day
co P = 19..132B): cung cong thuc padding SM3, chi precompute state prefix truoc
block chua 2 byte bien. Spot-check bang it.sm3 tai runtime.

Chay:  python _psk_sweep.py        (tu thu muc bat ky; path import theo __file__)
"""
import os, sys, re, json, time, base64, struct, glob
import multiprocessing as mp
import importlib.util

HERE  = os.path.dirname(os.path.abspath(__file__))
BASE  = r"D:\Tiktok-Android"
RESULT = os.path.join(HERE, "_psk_sweep_result.txt")

# ---- import codec da verify (KHONG phat minh lai) ----
spec = importlib.util.spec_from_file_location("it", os.path.join(HERE, "_inner_test.py"))
it = importlib.util.module_from_spec(spec); spec.loader.exec_module(it)

MAGIC6  = bytes.fromhex("08d2a4808204")           # HIT = report[:6]
TGT48   = int.from_bytes(MAGIC6, "little")
SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
HDR, TAIL, MODE, CUT, OFF, ZJ, ZREV = 9, 15, "revxor", None, 0, 4, False

# ============================================================================
# digest sweep tong quat: digests[n] = SM3(psk + (n>>8, n&0xff) + rb23 + psk)
# ============================================================================
_DGCACHE = {}

def digest_sweep(psk, rb23, ns=None):
    """ns=None -> ca 65536 (co cache); ns=list -> chi nhung n do (dung self-check)."""
    P = len(psk); M = 2 * P + 4
    pad = psk + b"\x00\x00" + rb23 + psk + b"\x80" + b"\x00" * ((55 - M) % 64) + struct.pack(">Q", M * 8)
    assert len(pad) % 64 == 0
    fb = P // 64                                   # block chua byte offset P
    V = list(it._SM3_IV)
    for i in range(0, fb * 64, 64):
        V = it.sm3_compress(V, pad[i:i + 64])
    region = bytearray(pad[fb * 64:])
    off = P - fb * 64
    assert 0 <= off and off + 2 <= len(region), "rb01 nam ngoai region?"
    def one(n):
        region[off]     = (n >> 8) & 0xFF
        region[off + 1] = n & 0xFF
        Vn = V
        for i in range(0, len(region), 64):
            Vn = it.sm3_compress(Vn, bytes(region[i:i + 64]))
        return struct.pack(">8I", *Vn)
    if ns is not None:
        return [one(n) for n in ns]
    key = (psk.hex(), rb23.hex())
    c = _DGCACHE.get(key)
    if c is not None:
        return c
    out = [one(n) for n in range(65536)]
    if len(_DGCACHE) >= 4:
        _DGCACHE.clear()
    _DGCACHE[key] = out
    return out

def digest_ref(psk, rb23, n):
    return it.sm3(psk + bytes(((n >> 8) & 0xFF, n & 0xFF)) + rb23 + psk)

# ============================================================================
# HMAC-SM3 tu viet (block 64B), DUNG sm3 cua _inner_test
# ============================================================================
def hmac_sm3(key, msg):
    if len(key) > 64:
        key = it.sm3(key)
    key = key + b"\x00" * (64 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return it.sm3(opad + it.sm3(ipad + msg))

# ============================================================================
# Walker varint-tag DUNG (copy tu _walk_mssdk.py: tag la varint, field>=16 tag
# 2 byte) — NHUNG KHONG in gia tri: chi tra ve (danh sach field#, trang thai)
# ============================================================================
def field_numbers(rep):
    i, n, fields = 0, len(rep), []
    while i < n:
        if rep[i] == 0:
            return fields, "stop-zeropad@%d/%d" % (i, n)
        tag = sh = 0; j = i
        while j < n:
            c = rep[j]; j += 1; tag |= (c & 0x7F) << sh
            if not c & 0x80:
                break
            sh += 7
            if sh > 28:
                return fields, "bad-tag-varint@%d" % i
        fn, wt = tag >> 3, tag & 7
        if fn == 0 or wt in (3, 4, 6, 7):
            return fields, "end-bad-tag@%d(fn=%d,wt=%d)" % (i, fn, wt)
        if wt == 0:
            v = s2 = 0
            while j < n:
                c = rep[j]; j += 1; v |= (c & 0x7F) << s2
                if not c & 0x80:
                    break
                s2 += 7
                if s2 > 63:
                    return fields, "bad-len-varint@#%d" % fn
            fields.append(fn)
        elif wt == 2:
            l = s2 = 0
            while j < n:
                c = rep[j]; j += 1; l |= (c & 0x7F) << s2
                if not c & 0x80:
                    break
                s2 += 7
            if l > n - j:
                return fields, "trunc-bytes@#%d(len=%d)" % (fn, l)
            j += l; fields.append(fn)
        elif wt == 5:
            j += 4; fields.append(fn)
        elif wt == 1:
            j += 8; fields.append(fn)
        i = j
    return fields, "ok"

# ============================================================================
# WORKER: 1 job = 1 ung vien x 1 pt — brute rb01 0..65535, check 6B magic o block dau
# ============================================================================
def psk_job(j):
    t0 = time.time()
    base = dict(label=j["label"], idx=j["idx"], ilen=j["ilen"])
    try:
        pt  = bytes.fromhex(j["pt_hex"])
        psk = bytes.fromhex(j["psk_hex"])
        simct = it.make_simct(pt, HDR, TAIL, MODE, CUT, OFF)
        if simct is None or len(simct) % 16:
            base.update(status="MISALIGN", secs=round(time.time() - t0, 1))
            return base
        rb23 = pt[-TAIL:-TAIL + 2]
        a0, b0 = struct.unpack("<QQ", simct[:16])
        digs = digest_sweep(psk, rb23)
        zb = it.zbits_of(ZJ, ZREV)
        up = struct.unpack
        hits = []
        for n in range(65536):
            rk = it.fast_key_expansion(up("<QQQQ", digs[n]), zb)
            a, _ = it.fast_dec_block(a0, b0, rk)
            if (a & 0xFFFFFFFFFFFF) == TGT48:
                hits.append(n)
        det = []
        for n in hits[:8]:
            rb01 = bytes((n >> 8, n & 0xFF))
            rep = it.full_decode(pt, rb01, psk, HDR, TAIL, MODE, CUT, OFF, ZJ, ZREV)
            if rep is None:
                det.append(dict(rb01=rb01.hex(), full6=None)); continue
            fset, wstat = field_numbers(rep)
            det.append(dict(rb01=rb01.hex(), full6=(rep[:6] == MAGIC6), replen=len(rep),
                            fields=sorted(set(fset)), wstat=wstat))
        base.update(status=("HIT" if hits else "MISS"), nhits=len(hits),
                    secs=round(time.time() - t0, 1), hits=det)
        return base
    except Exception as e:
        import traceback
        base.update(status="ERROR", err=repr(e), tb=traceback.format_exc()[-400:],
                    secs=round(time.time() - t0, 1))
        return base

# ============================================================================
# VAT LIEU OFFLINE (doc tu file, KHONG hardcode gia tri)
# ============================================================================
def load_materials():
    mat, miss = {}, []
    p1 = os.path.join(BASE, "cap.noindex", "msstate_7678616678053643790",
                      "device_secret_plaintext", "69c65eb55d99db36d7930f67a56c3f88.json")
    try:
        jj = json.load(open(p1, encoding="utf-8"))
        for short, full in (("s", "1233-0-1-sdi"), ("q", "1233-0-1-ecneuq"), ("t", "1233-0-1-semithc")):
            v = jj.get(full)
            if isinstance(v, str) and v:
                mat[short] = v.encode("ascii")
            else:
                miss.append("thieu key '%s' trong %s" % (full, os.path.basename(p1)))
    except Exception as e:
        miss.append("thieu file %s (%r)" % (p1, e))
    p2 = os.path.join(BASE, "cap.noindex", "msstate_7678616678053643790",
                      "device_secret_plaintext", "8fd6b14a691fe1b080863491fda3e89c.json")
    try:
        jj = json.load(open(p2, encoding="utf-8"))
        for k2 in ("dyn_seed", "rtk2_ms", "kiid", "dyn_deviceid"):
            v = jj.get(k2)
            if isinstance(v, str) and v:
                mat[k2] = v
            else:
                miss.append("thieu key '%s' trong %s" % (k2, os.path.basename(p2)))
    except Exception as e:
        miss.append("thieu file %s (%r)" % (p2, e))
    # b2a9d40c: grep gia tri 48B (96 hex) trong notes/43-*.md va notes/45-*.md
    b2 = None
    for pat in ("43-*.md", "45-*.md"):
        for fn in sorted(glob.glob(os.path.join(BASE, "notes", pat))):
            try:
                txt = open(fn, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            m2 = re.search(r"b2a9d40c[0-9a-f]{88}", txt)
            if m2:
                b2 = bytes.fromhex(m2.group(0))
                break
        if b2:
            break
    if b2:
        mat["b2"] = b2
    else:
        miss.append("b2a9d40c NOT FOUND (grep b2a9d40c[0-9a-f]{88} trong notes/43-*.md, notes/45-*.md)")
    return mat, miss

# ============================================================================
# SINH UNG VIEN SESSION_PSK — {label: psk_bytes}
# ============================================================================
def build_candidates(mat):
    L, LH = it.SIGN_KEY, it.SIGN_KEY.hex().encode()
    cands = {}
    def add(label, b):
        if b:
            cands.setdefault(label, bytes(b))
    have_sqt = all(k2 in mat for k2 in ("s", "q", "t"))
    if have_sqt:
        s, q, t = mat["s"], mat["q"], mat["t"]
        perms = [("s+q+t", s + q + t), ("s+t+q", s + t + q), ("q+s+t", q + s + t),
                 ("q+t+s", q + t + s), ("t+s+q", t + s + q), ("t+q+s", t + q + s)]
        # 1) concat-raw
        for k2, v in perms:
            add("raw:" + k2, v)
        add("raw:L+s+q+t", L + s + q + t);  add("raw:s+q+t+L", s + q + t + L)
        add("raw:L+t+q+s", L + t + q + s);  add("raw:t+q+s+L", t + q + s + L)
        add("raw:L+s+t+q", L + s + t + q);  add("raw:s+t+q+L", s + t + q + L)
        add("raw:Lhex+s+q+t", LH + s + q + t); add("raw:s+q+t+Lhex", s + q + t + LH)
        # 2) SM3-roi-dung
        for k2, v in perms:
            add("sm3:" + k2, it.sm3(v))
        add("sm3:L+s+q+t", it.sm3(L + s + q + t)); add("sm3:s+q+t+L", it.sm3(s + q + t + L))
        add("sm3:Lhex+s+q+t", it.sm3(LH + s + q + t))
        add("sm3:L+s", it.sm3(L + s)); add("sm3:L+q", it.sm3(L + q)); add("sm3:L+t", it.sm3(L + t))
        add("sm3:L+q+t", it.sm3(L + q + t)); add("sm3:L+t+q", it.sm3(L + t + q))
        # 3) XOR
        add("xor:L^sm3(s+q+t)", bytes(x ^ y for x, y in zip(L, it.sm3(s + q + t))))
        add("xor:L^sm3(s)",     bytes(x ^ y for x, y in zip(L, it.sm3(s))))
        add("xor:L^sm3(t+q)",   bytes(x ^ y for x, y in zip(L, it.sm3(t + q))))
        # 4) HMAC-SM3
        add("hmac:(L,s+q+t)", hmac_sm3(L, s + q + t)); add("hmac:(s+q+t,L)", hmac_sm3(s + q + t, L))
        add("hmac:(L,s)", hmac_sm3(L, s));             add("hmac:(L,q+t)", hmac_sm3(L, q + t))
        # 5) single
        add("raw:s", s); add("sm3:s", it.sm3(s))
    else:
        cands["_SKIP_SQT_"] = b""        # marker — se loai o dedup, chi de note
    if "rtk2_ms" in mat:
        add("raw:rtk2_ms", mat["rtk2_ms"].encode("ascii")); add("sm3:rtk2_ms", it.sm3(mat["rtk2_ms"].encode("ascii")))
    if "kiid" in mat:
        add("raw:kiid", mat["kiid"].encode("ascii")); add("sm3:kiid", it.sm3(mat["kiid"].encode("ascii")))
    if "dyn_deviceid" in mat:
        add("raw:dyn_deviceid", mat["dyn_deviceid"].encode("ascii"))
        add("sm3:dyn_deviceid", it.sm3(mat["dyn_deviceid"].encode("ascii")))
    if "dyn_seed" in mat:
        asc = mat["dyn_seed"].encode("ascii")
        add("raw:dyn_seed_ascii", asc); add("sm3:dyn_seed_ascii", it.sm3(asc))
        try:
            b64d = base64.b64decode(mat["dyn_seed"])
            add("raw:dyn_seed_b64d", b64d); add("sm3:dyn_seed_b64d", it.sm3(b64d))
        except Exception:
            pass
    if "b2" in mat:
        add("raw:b2a9d40c", mat["b2"]); add("raw:b2a9d40c[:32]", mat["b2"][:32])
        add("sm3:b2a9d40c", it.sm3(mat["b2"]))
    # 6) control
    add("ctrl:SIGN_KEY", L)
    # dedup theo gia tri (giu label dau)
    seen, dups, final = {}, [], {}
    for lab, b in cands.items():
        if not b:
            continue
        h = b.hex()
        if h in seen:
            dups.append("%s == %s" % (lab, seen[h]))
        else:
            seen[h] = lab; final[lab] = b
    return final, dups

# ============================================================================
# SELF-CHECKS (khong in secret — chi PASS/FAIL)
# ============================================================================
def selfchecks():
    ok = {}
    ok["sm3-abc"] = it.sm3(b"abc").hex() == SM3_ABC
    # digest_sweep == it.sm3 cho nhieu do dai psk (du lieu tong hop, khong phai secret)
    ns = [0, 1, 0x1234, 0xFF00, 0xFFFF]
    good = True
    for P in (19, 25, 26, 31, 32, 36, 48, 52, 63, 64, 65, 98, 132):
        psk = bytes((7 * i + 3) % 256 for i in range(P))
        rb23 = b"\xAB\xCD"
        got = digest_sweep(psk, rb23, ns=ns)
        ref = [digest_ref(psk, rb23, n) for n in ns]
        if got != ref:
            good = False
    ok["digest_sweep-spot(%d len x %d n)" % (13, len(ns))] = good
    # walker varint-tag: field>=16 phai an tag 2 byte
    rep = b"\x08\x96\x01" + b"\xa0\x01\x2a" + b"\x12\x03abc" + b"\xf8\x01\x02"
    f, st = field_numbers(rep)
    ok["walker(field20-2byte-tag)"] = (st == "ok" and f == [1, 20, 2, 31])
    # hmac property (khong co vector chuan external — kiem thuoc tinh)
    k1, k2 = b"\x0b" * 32, b"\x0b" * 31 + b"\x0c"
    ok["hmac-property"] = (hmac_sm3(k1, b"Hi There") != hmac_sm3(k2, b"Hi There")
                           and hmac_sm3(b"k" * 100, b"m") == hmac_sm3(it.sm3(b"k" * 100), b"m"))
    # Simon fast == reference
    import random as _r
    rr = _r.Random(1)
    good2 = True
    for _ in range(3):
        kl = [rr.getrandbits(64) for _ in range(4)]
        a, b = rr.getrandbits(64), rr.getrandbits(64)
        rk = it.simon_key_expansion(kl, ZJ, ZREV)
        if rk != it.fast_key_expansion(list(kl), it.zbits_of(ZJ, ZREV)):
            good2 = False
        if it.simon_dec_block(a, b, rk) != it.fast_dec_block(a, b, rk):
            good2 = False
    ok["simon-fast==ref"] = good2
    return ok

# ============================================================================
# MAIN
# ============================================================================
def main():
    out = open(RESULT, "w", encoding="utf-8")
    def W(s=""):
        try:
            print(s, flush=True)
        except UnicodeEncodeError:
            print(s.encode("ascii", "replace").decode("ascii"), flush=True)
        out.write(s + "\n"); out.flush()

    W("_psk_sweep.py — OFFLINE rotated-SESSION_PSK sweep cho mau MISS (L in {592,608})")
    W("time: %s | codec: _inner_test.py (full_decode 9/15 revxor z4, KHONG sua)" % time.strftime("%Y-%m-%d %H:%M:%S"))
    W("HIT = report[:6] == 08d2a4808204; rb01 brute 0..65535 (rb01=(n>>8,n&0xff) => BAO TRON 65536 gia tri 2-byte)")
    W("")

    # ---- vat lieu ----
    mat, miss = load_materials()
    W("[VAT LIEU]")
    for k2 in ("s", "q", "t", "dyn_seed", "rtk2_ms", "kiid", "dyn_deviceid", "b2"):
        W("  %-13s %s" % (k2, ("OK (%dB)" % len(mat[k2])) if (k2 in mat and k2 != "dyn_seed") else
                          ("OK (%d chars)" % len(mat[k2])) if k2 in mat else "MISSING"))
    for m2 in miss:
        W("  [MISS] %s" % m2)
    W("")

    # ---- self-checks ----
    W("[SELF-CHECK]")
    sc = selfchecks()
    for k2, v in sc.items():
        W("  %-34s %s" % (k2, "PASS" if v else "FAIL"))
    if not all(sc.values()):
        W("SELF-CHECK FAIL -> DUNG (so lieu brute se vo nghia).")
        out.close(); return
    W("")

    # ---- parse pts ----
    try:
        pts, skipped = it.parse_pts()
    except Exception as e:
        W("PARSE FAIL: %r -> DUNG." % e); out.close(); return
    miss_band = [(i, L, p) for i, L, p in pts if L in (592, 608)]
    hit_band  = [(i, L, p) for i, L, p in pts if L in (544, 560, 576)]
    W("[PTS] giu %d (bo %d); MISS-band L{{592,608}} = %d pt; HIT-band L{{544,560,576}} = %d pt"
      % (len(pts), len(skipped), len(miss_band), len(hit_band)))
    if not miss_band or not hit_band:
        W("MISS/HIT band rong -> DUNG."); out.close(); return
    ctrl_pt = hit_band[0]
    nproc = min(32, mp.cpu_count())
    W("")

    def mkjob(label, psk, iev, L, p):
        return dict(label=label, idx=iev, ilen=L, pt_hex=p.hex(), psk_hex=psk.hex())

    # ---- CONTROL 1: SIGN_KEY x HIT-band pt (phai HIT; neu khong => harness sai, DUNG) ----
    W("[CONTROL] SIGN_KEY x HIT-band pt idx%s L=%d (ky vong: HIT)" % (ctrl_pt[0], ctrl_pt[1]))
    cres = psk_job(mkjob("ctrl:SIGN_KEY", it.SIGN_KEY, *ctrl_pt))
    W("  -> %s (%ss)" % (cres["status"], cres.get("secs")))
    if cres["status"] != "HIT" or not cres.get("hits") or cres["hits"][0].get("full6") is not True:
        W("  !! CONTROL FAIL — HARNESS SAI, DUNG (bao lai, khong chay sweep).")
        out.close(); return
    h0 = cres["hits"][0]
    W("  rb01=%s full_decode 6B-magic=OK len=%d fields=%s wstat=%s -> HARNESS OK"
      % (h0["rb01"], h0["replen"], h0["fields"], h0["wstat"]))
    W("")

    # ---- CONTROL 2: xac dinh MISS THAT (pt ma SIGN_KEY khong giai du 65536 rb01) ----
    # Lan chay dau tien chon PT0 = "pt dau tien L=592" = idx81 — nhung brute chung to
    # idx81 GIAI DUOC bang SIGN_KEY (rb01=f9d5, report 560B field 1..36) => idx81 thuoc
    # nhom 74/92 HIT goc (73 HIT-band + idx81), KHONG thuoc 18 mau MISS. Vi vay PT0 phai
    # la pt dau tien ma SIGN_KEY MISS (brute, khong gia dinh).
    W("[CONTROL 2] brute SIGN_KEY tren ca %d pt MISS-band de xac dinh MISS that:" % len(miss_band))
    t_c2 = time.time()
    c2jobs = [mkjob("ctrl:SIGN_KEY", it.SIGN_KEY, *pt3) for pt3 in miss_band]
    c2res = []
    try:
        with mp.Pool(nproc) as pool:
            for res in pool.imap_unordered(psk_job, c2jobs, chunksize=1):
                c2res.append(res)
                W("  %s idx%s L=%d" % ("HIT " if res["status"] == "HIT" else "miss", res["idx"], res["ilen"]))
    except Exception as e:
        W("  control2 pool error: %r" % e)
    hitset = {r["idx"] for r in c2res if r["status"] == "HIT"}
    true_miss = [pt3 for pt3 in miss_band if pt3[0] not in hitset]
    W("  SIGN_KEY giai %d/%d miss-band pt => MISS that = %d pt: idx %s (%ds)"
      % (len(hitset), len(miss_band), len(true_miss), [pt3[0] for pt3 in true_miss], int(time.time() - t_c2)))
    if not true_miss:
        W("  !! SIGN_KEY giai het miss-band — khong con pt MISS de sweep. DUNG.")
        out.close(); return
    PT0 = true_miss[0]
    W("PT0 (dai dien MISS that) = idx%s L=%d rb23=%s" % (PT0[0], PT0[1], PT0[2][-15:-13].hex()))
    W("")

    # ---- candidates ----
    cands, dups = build_candidates(mat)
    W("[CANDIDATES] %d (sau dedup):" % len(cands))
    for lab, b in cands.items():
        W("  %-24s %dB" % (lab, len(b)))
    for d in dups:
        W("  [dup] %s" % d)
    W("")

    # ---- sweep PT0 ----
    W("[SWEEP PT0] moi job = 1 candidate x brute 65536 rb01 tren PT0:")
    jobs = [mkjob(lab, pb, *PT0) for lab, pb in cands.items()]
    t0 = time.time()
    results = []
    SOFT_CAP = 4800
    pool_break = False
    W("  workers = %d, jobs = %d" % (nproc, len(jobs)))
    try:
        with mp.Pool(nproc) as pool:
            done = 0
            for res in pool.imap_unordered(psk_job, jobs, chunksize=1):
                done += 1
                results.append(res)
                if res["status"] == "HIT":
                    W("  [HIT ] %-24s nhits=%d (%ss, %d/%d done)"
                      % (res["label"], res.get("nhits", 0), res.get("secs", -1), done, len(jobs)))
                    for h in res.get("hits", []):
                        W("        rb01=%s full6=%s len=%s fields=%s wstat=%s"
                          % (h["rb01"], h.get("full6"), h.get("replen"), h.get("fields"), h.get("wstat")))
                elif res["status"] == "ERROR":
                    W("  [ERR ] %-24s %s (%d/%d)" % (res["label"], res.get("err"), done, len(jobs)))
                else:
                    W("  [miss] %-24s (%ss, %d/%d)" % (res["label"], res.get("secs", -1), done, len(jobs)))
                if time.time() - t0 > SOFT_CAP:
                    W("  !! vuot soft-cap %ds -> dung dispatch" % SOFT_CAP)
                    pool.terminate(); pool_break = True
                    break
    except Exception as e:
        W("  pool error: %r" % e)
    W("  sweep thoi luong: %ds%s" % (int(time.time() - t0), " (SOFT-CAP CUT)" if pool_break else ""))
    W("")

    # ---- verify: candidate HIT PT0 => brute lai tren TAT CA miss-band ----
    pt0_hits = [r for r in results if r["status"] == "HIT"]
    if pt0_hits:
        W("[VERIFY] tung candidate HIT PT0 tren toan %d pt MISS that:" % len(true_miss))
        vjobs, vmap = [], []
        for r in pt0_hits:
            psk = cands[r["label"]]
            for iev, L, p in true_miss:
                vmap.append(r["label"])
                vjobs.append(mkjob(r["label"], psk, iev, L, p))
        t1 = time.time()
        vres = []
        try:
            with mp.Pool(nproc) as pool:
                for res in pool.imap_unordered(psk_job, vjobs, chunksize=1):
                    vres.append(res)
                    if res["status"] == "HIT":
                        h = res.get("hits", [{}])[0]
                        W("  [HIT ] %-24s pt idx%s L=%d rb01=%s fields=%s wstat=%s"
                          % (res["label"], res["idx"], res["ilen"], h.get("rb01"), h.get("fields"), h.get("wstat")))
                    else:
                        W("  [miss] %-24s pt idx%s L=%d (%s)"
                          % (res["label"], res["idx"], res["ilen"], res["status"]))
                    if time.time() - t1 > SOFT_CAP:
                        W("  !! vuot soft-cap -> dung verify"); pool.terminate(); break
        except Exception as e:
            W("  verify pool error: %r" % e)
        for r in pt0_hits:
            sub = [v for v in vres if v["label"] == r["label"] and v["status"] == "HIT"]
            allf = set()
            for v in sub:
                for h in v.get("hits", []):
                    allf.update(h.get("fields") or [])
            W("  ==> %s: giai %d/%d pt MISS that; field-set union = %s" % (r["label"], len(sub), len(true_miss), sorted(allf)))
            W("      targets: %s" % {t2: (t2 in allf) for t2 in (13, 14, 16, 17, 18, 19, 20, 24)})
    else:
        W("[VERIFY] khong co candidate nao HIT PT0 — bo qua.")

    # ---- summary ----
    W("")
    W("SWEEP: %d tried, %d hit PT0" % (len(results), len(pt0_hits)))
    if not pt0_hits:
        W("=> 0 HIT — offline derivation cua rotated PSK that bai tren toan bo gia thuyet da liet ke."
          " (%d mau MISS that khong giai duoc bang bat ky psk nao trong %d candidate)" % (len(true_miss), len(cands)))
    out.close()

if __name__ == "__main__":
    main()
