#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rebuild_inner_report.py — Parse + INJECT + re-serialize INNER report cua X-Argus (byte-exact).

  Muc dich: cong cu tai-dung report. Lay 1 report phone that (plaintext memcpy) -> THAY cac field
  device-bound (device_id #5, device_token #16, uuid16 #18, attestation #24, blob24 #32) bang cua
  device DICH -> xuat report protobuf hop le. San sang cho ngay co OUTER-encrypt (hoac feed vao sign).

  KHONG bia gia tri: chi hoan doi field ban CUNG CAP (tu capture device dich). Field per-request
  (#3/#12/#17/#19/#26/#31/#34-36) PHAI de sign-path tu tinh — tool nay khong gia mao chung.

  Bao dam: serialize(parse(x)) == x  (round-trip byte-exact) — self-test o cuoi.

  Dung:
    python scripts/rebuild_inner_report.py                       # self-test round-trip + in layout
    python scripts/rebuild_inner_report.py --set 5=<device_id> --set 16=<device_token_b64> \
           --set 24=<attestation_b64> --out out/report_injected.bin
"""
import os, sys, base64

ROOT = os.path.join(os.path.dirname(__file__), "..")
BINP = os.path.join(ROOT, "ground-truth", "xargus_inner_report_45.7.3.bin")

# ── varint ──
def read_varint(b, i):
    s = r = 0
    while i < len(b):
        x = b[i]; i += 1; r |= (x & 0x7f) << s
        if not (x & 0x80): return r, i
        s += 7
    raise ValueError("varint EOF")

def write_varint(n):
    out = bytearray()
    while True:
        x = n & 0x7f; n >>= 7
        out.append(x | (0x80 if n else 0))
        if not n: break
    return bytes(out)

# ── parse: giu NGUYEN raw record de round-trip byte-exact ──
def parse(b):
    """-> list of dict{start,end,field,wire,payload_off,payload,raw_record}"""
    fields = []; i = 0; n = len(b)
    while i < n:
        st = i
        tag, j = read_varint(b, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            _, j = read_varint(b, j); ps = None; pl = b[i:j]
        elif wt == 2:
            ln, k = read_varint(b, j); ps = k; j = k + ln; pl = b[ps:ps+ln]
        elif wt == 5:
            ps = j; j = j + 4; pl = b[ps:j]
        elif wt == 1:
            ps = j; j = j + 8; pl = b[ps:j]
        else:
            # unknown wire (group/deprecated) — stop, giu phan con lai raw
            fields.append({"field": None, "wire": None, "raw": b[i:], "payload": b[i:], "payload_off": i})
            return fields
        fields.append({"start": st, "end": j, "field": fn, "wire": wt,
                       "payload_off": ps, "payload": pl, "raw": b[st:j]})
        i = j
    return fields

def encode_record(fn, wt, payload):
    tag = write_varint((fn << 3) | wt)
    if wt == 2:
        return tag + write_varint(len(payload)) + payload
    return tag + payload  # wt0 payload already includes the varint bytes

def serialize(fields):
    out = bytearray()
    for f in fields:
        if f.get("field") is None:
            out += f["raw"]; continue
        # neu payload doi so voi raw -> re-encode; nguoc lai giu raw (byte-exact)
        rec = encode_record(f["field"], f["wire"], f["payload"]) if f.get("_dirty") else f["raw"]
        out += rec
    return bytes(out)

def inject(fields, field_num, new_payload_bytes):
    for f in fields:
        if f.get("field") == field_num and f["wire"] == 2:
            f["payload"] = new_payload_bytes
            f["_dirty"] = True
            return True
    return False

# ── CLI ──
def main():
    b = open(BINP, "rb").read()
    fields = parse(b)

    # SELF-TEST round-trip
    rt = serialize(fields)
    ok = rt == b
    print("[self-test] round-trip byte-exact: %s (%d B)" % (ok, len(rt)))
    assert ok, "round-trip FAILED — parser khong bao toan"

    sets = []
    out_path = None
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == "--set" and i+1 < len(a):
            k, v = a[i+1].split("=", 1); sets.append((int(k), v)); i += 2
        elif a[i] == "--out" and i+1 < len(a):
            out_path = a[i+1]; i += 2
        else:
            i += 1

    INJECTABLE = {5, 6, 16, 18, 24, 32}   # device-bound static fields an toan de hoan doi
    for k, v in sets:
        if k not in INJECTABLE:
            print("[!] field #%d KHONG nam trong nhom injectable %s — bo qua (per-request field phai de sign-path tinh)" % (k, sorted(INJECTABLE)))
            continue
        # value: neu #5/#6 la so ascii; #16/#24 la base64 text (report luu chinh text base64)
        payload = v.encode() if (k in (5, 6) or _looks_b64_text(v)) else base64.b64decode(v)
        okc = inject(fields, k, payload)
        print("[inject] #%d <- %r  (%s)" % (k, v[:24], "OK" if okc else "NOT FOUND"))

    if sets:
        newb = serialize(fields)
        print("[out] new report = %d B (was %d)" % (len(newb), len(b)))
        if out_path:
            open(out_path, "wb").write(newb); print("[out] saved -> %s" % out_path)

    # in layout ngan
    print("\nfield  wire  size  value")
    for f in fields:
        if f.get("field") is None: continue
        pl = f["payload"]
        if f["wire"] == 2:
            txt = pl.decode("latin1") if all(32 <= c < 127 for c in pl[:20]) else pl[:12].hex()
            print("#%-3d   %d     %-4d  %s" % (f["field"], f["wire"], len(pl), txt[:44]))
        else:
            # pl (wt0) = raw record (tag+value); bo qua tag roi doc value
            _, off = read_varint(pl, 0)
            v, _ = read_varint(pl, off)
            print("#%-3d   %d     -     %d" % (f["field"], f["wire"], v))

def _looks_b64_text(v):
    return all(c.isalnum() or c in "+/=-_" for c in v) and len(v) >= 16

if __name__ == "__main__":
    main()
