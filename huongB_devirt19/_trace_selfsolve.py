#!/usr/bin/env python3
"""Tái dựng memory CHỈ từ rf-sequence của _vm_trace.jsonl (không cần page capture),
rồi đọc slot16. Kiểm tra trace tự-nhất-quán có ra slot16 không.
  op18 load : addr = rf_cur[base]+off ; value = rf_next[dst]   -> mem[addr]=value
  op42 store: addr = rf_cur[isrc]+off ; value = rf_cur[idst]   -> mem[addr]=value
  slot16    = mem[*(x4+8)]  (x4 = reg[4] ở rf cuối/đầu)
"""
import os, json, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compute_slot16 import decode_op18, decode_op42, MASK64

HERE = os.path.dirname(os.path.abspath(__file__))
tr = os.path.join(HERE, "_vm_trace.jsonl")
lines = [json.loads(x) for x in open(tr)]

def rf_regs(h):
    b = bytes.fromhex(h)
    return [int.from_bytes(b[i*8:i*8+8], "little") for i in range(len(b)//8)]

mem = {}   # addr(byte) -> single byte
def w64(a, v):
    for i in range(8):
        mem[a+i] = (v >> (8*i)) & 0xff
def r64(a):
    v = 0; ok = True
    for i in range(8):
        b = mem.get(a+i)
        if b is None: ok = False; b = 0
        v |= b << (8*i)
    return v, ok

loads = stores = load_known = 0
for k in range(len(lines)-1):
    l = lines[k]; nxt = lines[k+1]
    op = l["op"]; word = int(l["word"], 16) & 0xffffffff
    rc = rf_regs(l["rf"]); rn = rf_regs(nxt["rf"])
    if op == 18:
        base, dst, off = decode_op18(word)
        addr = (rc[base] + off) & MASK64
        val = rn[dst]                    # giá trị thực đã nạp (ground truth)
        w64(addr, val); loads += 1
    elif op == 42:
        isrc, idst, off = decode_op42(word)
        addr = (rc[isrc] + off) & MASK64
        w64(addr, rc[idst]); stores += 1

# rf cuối cùng
rf_last = rf_regs(lines[-1]["rf"])
rf0 = rf_regs(lines[0]["rf"])
print(f"[trace] lines={len(lines)} loads={loads} stores={stores} mem_bytes={len(mem)}")
for tag, rf in (("rf0", rf0), ("rf_last", rf_last)):
    x4 = rf[4]
    dptr, ok = r64(x4 + 8)
    sl = bytes((mem.get(dptr+i, 0) for i in range(16)))
    inSSO = bytes((mem.get(x4+8+i, 0) for i in range(16)))  # nếu SSO: 16B ngay tại x4+8
    print(f"[{tag}] x4={x4:#x} dptr={dptr:#x}(known={ok}) slot16@dptr={sl.hex()}  slot16@x4+8(SSO)={inSSO.hex()}")

# thử mọi register làm 'x4' để dò outbuf (F output object) — tìm cái cho slot16 giống golden
rows = json.load(open(os.path.join(HERE, "_corr_data.json")))
golden = set(r["slot16"] for r in rows)
print(f"[golden] {len(golden)} slot16 targets, e.g. {list(golden)[:2]}")
hits = []
for rf, tag in ((rf0,"rf0"),(rf_last,"rfL")):
    for ri in range(32):
        base = rf[ri]
        for off in (0, 8, 16):
            dptr, ok = r64(base + off)
            if not ok: continue
            for doff in (0, 8, 16):
                sl = bytes((mem.get(dptr+doff+i, 0) for i in range(16))).hex()
                if sl in golden:
                    hits.append((tag, ri, off, doff, sl))
            # direct (SSO)
            sl2 = bytes((mem.get(base+off+i, 0) for i in range(16))).hex()
            if sl2 in golden:
                hits.append((tag+"-direct", ri, off, None, sl2))
print(f"[scan] golden hits: {len(hits)}")
for h in hits[:20]:
    print("   ", h)
