#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_inner_report.py — Phan tich INNER report cua X-Argus tu PLAINTEXT da bat qua memcpy.

  Nguon su that = ground-truth/xargus_inner_report_45.7.3.bin (640B, protobuf, bat tai memcpy
  TRUOC AES — note 30) + xargus_inner_reports_18x.json (18 mau de phan loai static/dynamic).

  KHONG can AES key/IV: plaintext da co san. (Script decrypt_inner_report.py chi dung khi/neu
  co OUTER key/IV — hien repo CHUA co key Android, decrypt ra rac entropy>7.5.)

  Lam gi:
    1. Parse protobuf top-level -> bang offset layout (field, wire, size).
    2. Diff N mau -> danh dau S (static, giong het) / D (dynamic, doi moi request).
    3. Kiem chung: dyn_seed (out/CAPTURED_DYN_SEED.txt) co nam trong report khong.
    4. (Tuy chon) Neu co KEY=/IV= -> thu AES-CBC decrypt 5 mau ciphertext + entropy self-check.
    5. Xuat out/inner_layout.md

  Dung:
    python scripts/analyze_inner_report.py
    KEY=<hex> IV=<hex> python scripts/analyze_inner_report.py   # kem thu decrypt outer
"""
import os, sys, json, math, base64, re
from collections import Counter

ROOT = os.path.join(os.path.dirname(__file__), "..")
GT   = os.path.join(ROOT, "ground-truth")
OUT  = os.path.join(ROOT, "out"); os.makedirs(OUT, exist_ok=True)

def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

# ── protobuf top-level walker (bounded, khong crash tren tail rac) ──
def rv(b, i):
    s = r = 0
    while i < len(b):
        x = b[i]; i += 1; r |= (x & 0x7f) << s
        if not (x & 0x80): return r, i, True
        s += 7
    return r, i, False

def walk(b):
    out = []; i = 0; n = len(b)
    while i < n:
        st = i
        tag, i, ok = rv(b, i)
        if not ok: break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i, ok = rv(b, i)
            if not ok: break
            out.append((st, i, fn, wt, None, v))
        elif wt == 2:
            ln, i, ok = rv(b, i)
            if not ok or i + ln > n: break
            ps = i; i += ln
            out.append((st, i, fn, wt, ln, b[ps:ps + ln]))
        elif wt == 5:
            if i + 4 > n: break
            out.append((st, i + 4, fn, wt, 4, b[i:i + 4])); i += 4
        elif wt == 1:
            if i + 8 > n: break
            out.append((st, i + 8, fn, wt, 8, b[i:i + 8])); i += 8
        else:
            break
    return out, i

def preview(wt, raw, ln):
    if wt == 2:
        b = bytes(raw)
        if b and all(32 <= c < 127 for c in b[:24]):
            return b[:24].decode("latin1")
        return b[:18].hex()
    return str(raw)

# guess semantic label from value (chi de doc; KHONG phai ket luan)
def label(fn, wt, raw, ln, sd):
    if wt == 2 and isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
        try: s = b.decode("ascii")
        except Exception: s = ""
        if s == "1233": return "aid"
        if s.isdigit() and ln == 19: return "device_id"
        if s == "45.7.3": return "app_ver"
        if s.startswith("v05.") and "ov-android" in s: return "metasec_sdk_ver"
        if s.isdigit() and ln == 10: return "id_phu(cd?)"
        if ln == 25 and s and "-" in s: return "device_token(server-issued?)"
        if ln == 132: return ">>> ATTESTATION/device-state blob <<<"
        if ln == 16 and sd == "S": return "uuid16 device-bound"
        if ln == 32 and sd.startswith("D"): return "req_hash/sig per-request"
        if ln == 24 and sd == "S": return "blob24 device-bound"
        if b[:1] == b"\x0a": return "nested{...}"
    if wt == 0:
        if sd.startswith("D") and raw and raw > 10**9: return "ts/counter or sig-part"
    return ""

def main():
    binp = os.path.join(GT, "xargus_inner_report_45.7.3.bin")
    main_b = open(binp, "rb").read()
    samples = [bytes.fromhex(s["hex"]) for s in json.load(open(os.path.join(GT, "xargus_inner_reports_18x.json")))]
    f0, end0 = walk(main_b)
    walks = [walk(s)[0] for s in samples]
    minf = min(len(w) for w in walks)
    N = min(len(f0), minf)

    lines = []
    def p(*a): s = " ".join(str(x) for x in a); print(s); lines.append(s)

    p("# X-Argus INNER report — layout (nguon: memcpy plaintext, KHONG decrypt)\n")
    p("- report len = %d B (protobuf), entropy = %.3f" % (len(main_b), entropy(main_b)))
    p("- parse sach den 0x%x, tail 0x%x..0x%x = config JSON (ECH/QUIC ip_endpoints), khong phan tich"
      % (end0, end0, len(main_b)))
    p("- so mau diff = %d (tat ca len=640)\n" % len(samples))
    p("| idx | offset | field# | wire | size | S/D | value/preview | label |")
    p("|----|--------|--------|------|------|-----|---------------|-------|")
    static_devstate = []
    for k in range(N):
        st, en, fn, wt, ln, raw = f0[k]
        vals = set()
        for w in walks:
            r = w[k][5]
            vals.add(bytes(r) if wt == 2 else r)
        sd = ("D%d" % len(vals)) if len(vals) > 1 else "S"
        lb = label(fn, wt, raw, ln, sd)
        pv = preview(wt, raw, ln).replace("|", "\\|")[:40]
        p("| %d | 0x%03x-0x%03x | #%d | %d | %s | %s | `%s` | %s |"
          % (k, st, en - 1, fn, wt, str(ln), sd, pv, lb))
        if sd == "S" and wt == 2 and ln and ln >= 16 and fn in (16, 18, 24, 32):
            static_devstate.append((fn, st, ln))

    # dyn_seed presence
    p("\n## dyn_seed check")
    seed_txt = open(os.path.join(OUT, "CAPTURED_DYN_SEED.txt")).read()
    sh = re.search(r"hex=([0-9a-f]+)", seed_txt).group(1)
    rep_hex = main_b.hex()
    full = sh in rep_hex
    chunk = any(sh[i:i+32] in rep_hex for i in range(0, len(sh) - 32, 2))
    p("- dyn_seed = %d B" % (len(sh)//2))
    p("- dyn_seed FULL trong report: **%s**" % full)
    p("- dyn_seed 16B-chunk trong report: **%s**" % chunk)
    p("- => %s" % ("dyn_seed KHONG phai field cua report; la keying material cho ky (#19/#34-36)."
                   if not (full or chunk) else "dyn_seed xuat hien trong report (xem lai)."))

    # device-state static fields (cai offline thieu)
    p("\n## Static device-bound fields (cai offline KHO/KHONG dung duoc)")
    tot = 0
    for fn, st, ln in static_devstate:
        p("- #%d @0x%03x  %dB" % (fn, st, ln)); tot += ln
    p("- **Tong static device-state = %d B** (chua ke sig dynamic phu thuoc state)" % tot)

    # optional outer decrypt self-check
    KEY = os.environ.get("KEY"); IV = os.environ.get("IV")
    if KEY and IV:
        p("\n## OUTER decrypt self-check")
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            key = bytes.fromhex(KEY); iv = bytes.fromhex(IV)
            gx = json.load(open(os.path.join(GT, "genuine_xargus_45.7.3.json")))
            good = 0
            for i, s in enumerate(gx):
                m = re.search(r"X-Argus\r?\n([^\r\n]+)", s["hdr"]);
                if not m: continue
                raw = base64.b64decode(m.group(1)); ct = raw[2:]
                if len(ct) % 16: continue
                d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                pt = d.update(ct) + d.finalize()
                e = entropy(pt[16:])
                ok = e < 6.5 and 1 <= pt[-1] <= 16
                good += ok
                p("- [%d] pt=%dB entropy(rest)=%.2f -> %s" % (i, len(pt), e, "PLAINTEXT" if ok else "GARBAGE(wrong key/iv)"))
            p("- verdict: %d/%d plaintext -> %s" % (good, len(gx),
              "KEY/IV DUNG" if good else "WRONG KEY/IV (entropy cao = rac)"))
        except Exception as ex:
            p("- loi decrypt:", ex)
    else:
        p("\n## OUTER decrypt: bo qua (khong co KEY=/IV=). "
          "Repo hien CHUA co key Android — out/inner_report_plain.json la rac (entropy 7.6).")

    md = os.path.join(OUT, "inner_layout.md")
    open(md, "w", encoding="utf-8").write("\n".join(lines))
    print("\n[*] saved -> %s" % md)

if __name__ == "__main__":
    main()
