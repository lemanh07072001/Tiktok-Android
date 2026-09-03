#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re_recon2.py — Recon TINH (robust) cho libmetasec_ov.so ARM64 OLLVM.

Sua 2 loi cua ban 1:
  - Linear sweep chet o data-island -> disasm_all() skip-4 khi fail, phu toan .text.
  - 0x11c580 la duoi ham -> tim prologue that (backward) + map ret/prologue.
Them:
  - Xref toan cuc (ADRP+ADD va ADRP+LDR) -> resolve string references.
  - Dac ta obfuscation dung tren TOAN BO .text.

Dung: py re_recon2.py <libmetasec_ov.so> [target_offset_hex]
"""
import sys
from collections import Counter, defaultdict

import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import (ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM,
                            ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_BR,
                            ARM64_INS_BLR, ARM64_INS_LDR, ARM64_INS_RET,
                            ARM64_INS_STP, ARM64_INS_BL, ARM64_INS_B,
                            ARM64_INS_CBZ, ARM64_INS_CBNZ)

LIB = sys.argv[1]
TARGET = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x11c580

bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()

secs = {s.name: (s.virtual_address, s.offset, s.size) for s in bin_.sections if s.size}
tv0, to0, tsz0 = secs[".text"]
text_code = raw[to0: to0 + tsz0]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def disasm_all(code, base_va):
    """Robust linear sweep: skip 4 bytes khi capstone fail (ARM64 fixed 4B)."""
    off, N = 0, len(code)
    while off < N:
        advanced = False
        for insn in md.disasm(code[off:], base_va + off):
            yield insn
            off = insn.address - base_va + insn.size
            advanced = True
        if not advanced:
            off += 4

print(f"=== RECON2: {LIB} ===")
print(f"[.text] vaddr=0x{tv0:x} size=0x{tsz0:x} ({tsz0:,}B)\n")

# ---- Pass 1: full sweep -> stats, xref index, ret/prologue map ----
mnem = Counter()
total = 0
undecodable = 0
br_addrs, blr_addrs, ret_addrs = [], [], []
prologue_addrs = []          # stp x{a},x{b},[sp,#-N]!  (func starts)
adrp_reg = {}                # reg -> (page, insn_addr)
xref = defaultdict(list)     # target_va -> [(insn_addr, kind)]
bl_targets = Counter()       # dia chi bi BL goi (de dem "hot" functions)

# de dem undecodable: so sanh so lenh voi so word ly thuyet
expected_words = tsz0 // 4

for insn in disasm_all(text_code, tv0):
    total += 1
    mnem[insn.mnemonic] += 1
    iid = insn.id
    if iid == ARM64_INS_ADRP:
        ops = insn.operands
        if len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            adrp_reg[ops[0].reg] = (ops[1].imm, insn.address)
    elif iid == ARM64_INS_ADD:
        ops = insn.operands
        if len(ops) == 3 and ops[2].type == ARM64_OP_IMM and ops[1].type == ARM64_OP_REG:
            src = ops[1].reg
            if src in adrp_reg:
                page, _ = adrp_reg[src]
                xref[page + ops[2].imm].append((insn.address, "ADRP+ADD"))
    elif iid == ARM64_INS_LDR:
        ops = insn.operands
        if len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            base = ops[1].mem.base
            disp = ops[1].mem.disp
            if base in adrp_reg:
                page, _ = adrp_reg[base]
                xref[page + disp].append((insn.address, "ADRP+LDR(GOT)"))
    elif iid == ARM64_INS_BR:
        br_addrs.append(insn.address)
    elif iid == ARM64_INS_BLR:
        blr_addrs.append(insn.address)
    elif iid == ARM64_INS_RET:
        ret_addrs.append(insn.address)
    elif iid == ARM64_INS_BL:
        ops = insn.operands
        if ops and ops[0].type == ARM64_OP_IMM:
            bl_targets[ops[0].imm] += 1
    elif iid == ARM64_INS_STP:
        # prologue: stp xA, xB, [sp, #-N]!  (writeback, negative)
        ops = insn.operands
        if len(ops) == 3 and ops[2].type == ARM64_OP_MEM:
            m = ops[2].mem
            if m.base == md.reg_name(ops[2].mem.base) or True:
                if m.disp < 0 and insn.writeback:
                    prologue_addrs.append(insn.address)

print("[1] Dac ta obfuscation (TOAN .text)")
print(f"    lenh giai ma / word ly thuyet : {total:,} / {expected_words:,}  ({100*total//max(expected_words,1)}%)")
print(f"    BR  (indirect branch/dispatch): {len(br_addrs):,}")
print(f"    BLR (indirect call)           : {len(blr_addrs):,}")
print(f"    RET                           : {len(ret_addrs):,}")
print(f"    prologue (stp ..,[sp,#-N]!)   : {len(prologue_addrs):,}  (~so ham)")
print(f"    Top 18 mnemonics:")
for m, c in mnem.most_common(18):
    print(f"        {m:8s} {c:>8,}")

# ---- Pass 2: strings + xref cho tu khoa ----
KEYWORDS = [b"safetyNet", b"integrity", b"basicIntegrity", b"ctsProfile",
            b"attest", b"nonce", b"get_seed", b"dyn_seed", b"device_id",
            b"deviceToken", b"PlayIntegrity", b"license", b"cronet"]
def cstr_at(off):
    lo = off
    while lo > 0 and 32 <= raw[lo-1] < 127: lo -= 1
    hi = off
    while hi < len(raw) and 32 <= raw[hi] < 127: hi += 1
    return lo, raw[lo:hi].decode("latin1", "replace")

print("\n[2] Strings + xref toan cuc")
for kw in KEYWORDS:
    i = raw.find(kw)
    if i < 0:
        continue
    lo, s = cstr_at(i)
    va = lo  # trong vung .rodata/.text va==off (kiem chung o ban 1)
    xr = xref.get(va, [])
    disp = s if len(s) <= 48 else s[:45] + "..."
    xr_s = ", ".join(f"0x{a:x}({k})" for a, k in xr[:6]) if xr else "(0 xref truc tiep)"
    print(f"    '{kw.decode():14s}' va=0x{va:x} {disp!r:52s} -> {xr_s}")

# ---- Pass 3: tim ham chua TARGET (backward toi prologue) ----
print(f"\n[3] Ham chua 0x{TARGET:x}")
# ret gan nhat truoc TARGET
prev_rets = [a for a in ret_addrs if a < TARGET]
next_rets = [a for a in ret_addrs if a >= TARGET]
prev_ret = max(prev_rets) if prev_rets else tv0
next_ret = min(next_rets) if next_rets else TARGET
# func start = prologue gan nhat <= TARGET va > prev_ret-vung
cands = [a for a in prologue_addrs if a <= TARGET]
func_start = max(cands) if cands else None
print(f"    ret ngay truoc TARGET   : 0x{prev_ret:x}")
print(f"    ret bao TARGET (>=)     : 0x{next_ret:x}")
print(f"    prologue gan nhat <=T   : " + (f"0x{func_start:x}" if func_start else "?"))

# disasm tu prologue toi het (den ret bao TARGET) — gioi han 120 lenh
if func_start:
    fstart_off = func_start - tv0
    span = (next_ret + 4) - func_start
    span = min(span, 120*4)
    print(f"\n[4] Disasm dispatcher tu 0x{func_start:x} ({span//4} lenh dau):")
    cnt = 0
    for insn in disasm_all(text_code[fstart_off:fstart_off+span], func_start):
        mark = ""
        if insn.id == ARM64_INS_BR: mark = "   <-- BR (dispatch/tail)"
        if insn.id in (ARM64_INS_CBZ, ARM64_INS_CBNZ): mark = "   (cond)"
        print(f"    0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}{mark}")
        cnt += 1
        if cnt >= 120: break

# ---- Pass 4: hot BL targets (ham duoc goi nhieu = helper OLLVM/crypto) ----
print(f"\n[5] Top 12 dia chi bi BL goi nhieu nhat (helper OLLVM/decrypt?):")
for tgt, c in bl_targets.most_common(12):
    zone = ".plt/external" if tgt < tv0 else ".text"
    print(f"    0x{tgt:x}  x{c:<4}  [{zone}]")

print("\n=== HET RECON2 ===")
