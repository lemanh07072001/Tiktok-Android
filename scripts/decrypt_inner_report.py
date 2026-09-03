#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt_inner_report.py — Decrypt INNER report cua X-Argus (OUTER = prefix2 || AES-CBC(report)).
  Input: genuine_xargus_45.7.3.json (5 mau that, da capture tu phone) + KEY/IV (ban cung cap).
  Output: plaintext hex/base64 tung mau + CHAN DOAN key/iv dung-sai + BANG OFFSET (diff 5 mau:
          byte GIONG nhau moi mau = STATIC field; byte KHAC = DYNAMIC field) + anchor gia tri da biet.

  Dung:
    KEY=<hex 32|64> IV=<hex 32> python scripts/decrypt_inner_report.py [json_path]
    # hoac positional:
    python scripts/decrypt_inner_report.py ground-truth/genuine_xargus_45.7.3.json <KEY_hex> <IV_hex>

  Chan doan (khong can biet truoc key dung):
    - PKCS7 padding hop le  + block0 co cau truc  -> KEY & IV DUNG (rat co the).
    - block0 rac, block1..36 co cau truc          -> KEY DUNG, IV SAI (CBC: IV chi hong block dau).
    - toan bo entropy cao/rac                      -> KEY SAI.
  => Neu WRONG KEY: bao ngay, chuyen Huong 2 (IDA offset) / Huong 3 (Stalker).
"""
import sys, os, json, base64, re, math
from collections import Counter

# ── args ──
JSON = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].endswith(".json") \
       else os.path.join(os.path.dirname(__file__), "..", "ground-truth", "genuine_xargus_45.7.3.json")
KEY_HEX = os.environ.get("KEY") or (sys.argv[2] if len(sys.argv) > 2 else "")
IV_HEX  = os.environ.get("IV")  or (sys.argv[3] if len(sys.argv) > 3 else "")

if not KEY_HEX or not IV_HEX:
    print("[!] Thieu KEY/IV. Chay lai:")
    print("    KEY=<hex 32 hoac 64 ky tu> IV=<hex 32 ky tu> python scripts/decrypt_inner_report.py")
    print("    (KEY 32hex=AES-128, 64hex=AES-256; IV 32hex=16 byte)")
    sys.exit(1)

try:
    KEY = bytes.fromhex(KEY_HEX.strip())
    IV  = bytes.fromhex(IV_HEX.strip())
except ValueError as e:
    print("[!] KEY/IV khong phai hex:", e); sys.exit(1)
if len(KEY) not in (16, 32):
    print(f"[!] KEY len={len(KEY)} — can 16 (AES-128) hoac 32 (AES-256)"); sys.exit(1)
if len(IV) != 16:
    print(f"[!] IV len={len(IV)} — can 16 byte"); sys.exit(1)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_cbc_dec(ct, key, iv):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()

def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def pkcs7_ok(pt):
    if not pt: return False
    p = pt[-1]
    return 1 <= p <= 16 and pt[-p:] == bytes([p]) * p

def printable_ratio(b):
    return sum(1 for x in b if 0x20 <= x < 0x7f) / max(1, len(b))

def ascii_view(b):
    return "".join(chr(x) if 0x20 <= x < 0x7f else "." for x in b)

# ── load samples ──
samples = json.load(open(JSON, encoding="utf-8"))
print(f"[*] {JSON}: {len(samples)} mau | KEY={len(KEY)}B AES-{len(KEY)*8} | IV={len(IV)}B\n")

plains = []
for i, s in enumerate(samples):
    hdr = s.get("hdr", "")
    m = re.search(r"X-Argus\r?\n([^\r\n]+)", hdr)
    if not m:
        print(f"[{i}] khong tim thay X-Argus"); continue
    raw = base64.b64decode(m.group(1))
    prefix2, ct = raw[:2], raw[2:]
    if len(ct) % 16 != 0:
        print(f"[{i}] ciphertext len={len(ct)} khong chia het 16 — bo qua"); continue
    pt = aes_cbc_dec(ct, KEY, IV)
    url = s.get("url", "")[:60]
    ok_pad = pkcs7_ok(pt)
    e_all = entropy(pt); e_b0 = entropy(pt[:16]); e_rest = entropy(pt[16:])
    pr = printable_ratio(pt)
    verdict = ("KEY+IV DUNG" if ok_pad and e_rest < 6.5 else
               "KEY DUNG / IV SAI (block0 rac)" if e_b0 > 7.2 and e_rest < 6.5 else
               "WRONG KEY (entropy cao)" if e_rest > 7.3 else "KHONG CHAC (xem hex)")
    print(f"[{i}] {url}")
    print(f"     prefix2={prefix2.hex()} ct={len(ct)}B pt={len(pt)}B | pad_ok={ok_pad} "
          f"ent(all/b0/rest)={e_all:.2f}/{e_b0:.2f}/{e_rest:.2f} printable={pr:.0%}")
    print(f"     >>> {verdict}")
    plains.append({"i": i, "url": s.get("url", ""), "pt": pt, "prefix2": prefix2})

if not plains:
    print("\n[!] khong decrypt duoc mau nao."); sys.exit(2)

# ── overall verdict ──
good = sum(1 for p in plains if pkcs7_ok(p["pt"]) and entropy(p["pt"][16:]) < 6.5)
print(f"\n[VERDICT] {good}/{len(plains)} mau co dau hieu plaintext hop le.")
if good == 0:
    print("  => NGHI WRONG KEY. Neu block0 rac + rest co cau truc thi la IV sai (thu IV khac / IV=00..).")
    print("  => Neu tat ca rac: KEY sai -> chuyen Huong 2 (IDA offset) hoac Huong 3 (Stalker). Bao 'WRONG KEY'.")

# ── BANG OFFSET: diff cac plaintext (byte giong moi mau = STATIC, khac = DYNAMIC) ──
L = min(len(p["pt"]) for p in plains)
static = bytearray(); dyn_mask = []
for off in range(L):
    vals = {p["pt"][off] for p in plains}
    dyn_mask.append(len(vals) > 1)
# gom thanh cac vung lien tiep
print("\n===== BANG OFFSET (diff %d mau) =====" % len(plains))
print("  [S]=static (giong het moi request = device/version/magic) | [D]=dynamic (ts/nonce/hash/seed)")
off = 0
while off < L:
    d = dyn_mask[off]; start = off
    while off < L and dyn_mask[off] == d:
        off += 1
    seg = plains[0]["pt"][start:off]
    kind = "D" if d else "S"
    prev = seg[:24].hex() + ("..." if len(seg) > 24 else "")
    txt = ascii_view(seg[:24])
    print(f"  0x{start:03x}-0x{off-1:03x} [{kind}] len={off-start:<3} {prev:<52} |{txt}")

# ── ANCHOR: tim gia tri da biet trong plaintext mau 0 ──
print("\n===== ANCHOR gia tri da biet (mau 0) =====")
pt0 = plains[0]["pt"]
url0 = plains[0]["url"]
anchors = {}
did = re.search(r"device_id=(\d+)", url0)
iid = re.search(r"(?:^|&)iid=(\d+)", url0)
kh  = re.search(r"X-Khronos\r?\n(\d+)", samples[plains[0]["i"]]["hdr"])
cands = []
if did: cands.append(("device_id", did.group(1)))
if iid: cands.append(("install_id", iid.group(1)))
cands += [("aid", "1233"), ("app_ver", "45.7.3"), ("version_code", "2024507030"), ("pkg", "musical")]
if kh:  cands.append(("khronos_sec", kh.group(1)))
for name, val in cands:
    hits = []
    # ascii
    p = pt0.find(val.encode())
    if p >= 0: hits.append(f"ascii@0x{p:x}")
    # int LE/BE (cho so)
    if val.isdigit():
        try:
            n = int(val)
            for width in (4, 8):
                for endi in ("little", "big"):
                    nb = n.to_bytes(width, endi)
                    q = pt0.find(nb)
                    if q >= 0: hits.append(f"int{width*8}{endi[0].upper()}E@0x{q:x}")
        except Exception: pass
    print(f"  {name:<14} = {val:<22} -> {', '.join(hits) if hits else 'khong thay'}")

# ── save ──
SP = os.path.join(os.path.dirname(__file__), "..", "out")
os.makedirs(SP, exist_ok=True)
outp = os.path.join(SP, "inner_report_plain.json")
json.dump([{"i": p["i"], "url": p["url"], "prefix2": p["prefix2"].hex(),
            "plaintext_hex": p["pt"].hex(),
            "plaintext_b64": base64.b64encode(p["pt"]).decode()} for p in plains],
          open(outp, "w"), indent=1)
print(f"\n[*] saved plaintext -> {outp}")
