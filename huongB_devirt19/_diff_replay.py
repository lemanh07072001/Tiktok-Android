#!/usr/bin/env python3
"""Differential replay: so rf-tôi-tính vs rf-ground-truth ghi trong _vm_trace.jsonl.
Tìm instruction ĐẦU TIÊN phân kỳ + register lệch + (với op18) địa chỉ đọc sai.
Trace mỗi dòng: {pc, word, op, rf(256B=32reg LE), stk}. rf = state TRƯỚC khi exec dòng đó.
Usage: python3 _diff_replay.py [singleshot.json]
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compute_slot16 import VM, decode_op18, decode_op42, MASK64

HERE = os.path.dirname(os.path.abspath(__file__))
ss = sys.argv[1] if len(sys.argv) > 1 else "_singleshot.json"
tr = os.path.join(HERE, "_vm_trace.jsonl")

def rf_regs(hexstr):
    b = bytes.fromhex(hexstr)
    return [int.from_bytes(b[i*8:i*8+8], "little") for i in range(len(b)//8)]

lines = [json.loads(x) for x in open(tr)]
print(f"[trace] {len(lines)} instrs; image={ss}")

# Kiểm định: rf là state TRƯỚC hay SAU? So rf[dòng k+1] vs rf tính được sau exec dòng k.
# Ta dùng rf dòng 0 làm khởi tạo regfile trong memory, rồi replay và so với rf các dòng sau.
vm = VM(os.path.join(HERE, ss))
r0 = rf_regs(lines[0]["rf"])
# overlay recorded rf[0] vào regfile để khởi tạo đúng ground-truth
for i, v in enumerate(r0):
    vm.setreg(i, v)

def cur_regs():
    return [vm.reg(i) for i in range(32)]

first_div = None
op18_addr_of = {}   # dst -> addr, để báo địa chỉ khi phân kỳ
div_count = 0
load_recorded_mismatch = 0
loads = 0
for k in range(len(lines)-1):
    l = lines[k]; nxt = lines[k+1]
    op = l["op"]; word = int(l["word"], 16) & 0xFFFFFFFF
    want_next = rf_regs(nxt["rf"])   # ground-truth rf SAU khi exec dòng k (= trước dòng k+1)
    if op == 18:
        base, dst, off = decode_op18(word)
        addr = (vm.reg(base) + off) & MASK64
        loads += 1
        val = vm.mem.r64(addr)
        # ground truth cho reg[dst] sau load:
        gt = want_next[dst]
        if val != gt:
            load_recorded_mismatch += 1
            if first_div is None:
                mapped = vm.mem.pages.get(addr & ~0xFFF) is not None
                first_div = (k, l["pc"], "op18", dst, base, off, addr, val, gt, mapped)
        vm.setreg(dst, val)
    elif op == 42:
        isrc, idst, off = decode_op42(word)
        vm.mem.w64((vm.reg(isrc) + off) & MASK64, vm.reg(idst))
    elif op == 44:
        pass
    # so toàn bộ rf sau exec vs ground-truth (chỉ đếm, để thấy tổng phân kỳ)
    cur = cur_regs()
    for i in range(32):
        if cur[i] != want_next[i]:
            div_count += 1
            break

print(f"[loads] {loads}  op18-load ≠ ground-truth reg[dst]: {load_recorded_mismatch}")
if first_div:
    k,pc,opn,dst,base,off,addr,val,gt,mapped = first_div
    print(f"\n[FIRST DIVERGENCE] line {k} pc={pc} {opn}")
    print(f"   reg[dst={dst}] = *(reg[base={base}] + {off})")
    print(f"   reg[base]={vmreg if False else ''}")
    print(f"   addr read = {addr:#x}  page_mapped={mapped}")
    print(f"   my value  = {val:#018x}")
    print(f"   GROUND TR = {gt:#018x}   <-- what the real device loaded here")
    # what was reg[base] at that point (from recorded rf of line k)
    rfk = rf_regs(lines[k]["rf"])
    print(f"   reg[base={base}] (recorded) = {rfk[base]:#018x}  -> +{off} = {(rfk[base]+off)&MASK64:#x}")
else:
    print("\n[NO DIVERGENCE] every op18 load matched ground-truth reg[dst]!")
print(f"\n[lines with ANY rf mismatch after exec] {div_count}/{len(lines)-1}")
