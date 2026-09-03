#!/usr/bin/env python3
"""Chẩn đoán miss-rate của replay F trên 1 ảnh singleshot bất kỳ.
Đo: tổng op18 load, số miss, phân bố base-register gây miss, và giá trị reg[6]
tại thời điểm miss (dấu vết call-out 0x13b010/0x13b034 chưa capture).
Usage: python3 _diag_miss.py [singleshot.json]
"""
import sys, os, json
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compute_slot16 import VM, decode_op18, decode_op42, MASK64

HERE = os.path.dirname(os.path.abspath(__file__))
ss = sys.argv[1] if len(sys.argv) > 1 else "_singleshot_ce0516.json"
tr = os.path.join(HERE, "_vm_trace.jsonl")

vm = VM(os.path.join(HERE, ss))
print(f"[image] {ss}  x24={vm.x24:#x} x4={vm.x4:#x} pages={len(vm.mem.pages)}")

loads = misses = 0
miss_base = Counter()      # base-register index -> count of misses via it
miss_baseval = Counter()   # high nibble of the base value (page family) -> count
reg6_samples = []

for l in (json.loads(x) for x in open(tr)):
    op = l["op"]; word = int(l["word"], 16) & 0xFFFFFFFF
    if op == 18:
        base, dst, off = decode_op18(word)
        addr = (vm.reg(base) + off) & MASK64
        loads += 1
        # is the target page mapped?
        if vm.mem.pages.get(addr & ~0xFFF) is None:
            misses += 1
            miss_base[base] += 1
            miss_baseval[(vm.reg(base) >> 32) & 0xffffffff] += 1
            if base == 6 and len(reg6_samples) < 8:
                reg6_samples.append((vm.reg(6), off, addr))
        vm.setreg(dst, vm.mem.r64(addr))
    elif op == 42:
        isrc, idst, off = decode_op42(word)
        vm.mem.w64((vm.reg(isrc) + off) & MASK64, vm.reg(idst))

print(f"[replay] op18 loads={loads}  misses={misses}  ({100*misses//max(loads,1)}%)")
print(f"[reg6 now] = {vm.reg(6):#x}")
print("[miss by base-reg] (reg_index: count)")
for r, c in miss_base.most_common(12):
    print(f"    reg[{r:2d}] : {c:4d}   base_val_now={vm.reg(r):#x}")
print("[miss base-value high32 families]")
for hv, c in miss_baseval.most_common(8):
    print(f"    hi32={hv:#010x} : {c}")
if reg6_samples:
    print("[reg6 miss samples] (reg6_val, off, target_addr)")
    for v, o, a in reg6_samples:
        print(f"    reg6={v:#x} off={o} -> {a:#x}")
print(f"\nslot16 (data_ptr view) = {vm.slot16().hex()}")
