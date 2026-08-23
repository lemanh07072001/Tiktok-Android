#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""find_getseed.py — Tim string lien quan get_seed/mssdk/report + xref (ADRP+ADD) -> ham builder 112B."""
import sys, re
from collections import defaultdict
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import (ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_LDR,
                            ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM)

LIB = sys.argv[1]
bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()
secs = {s.name: (s.virtual_address, s.offset, s.size) for s in bin_.sections if s.size}
tv0, to0, tsz = secs[".text"]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

def disasm_all(code, base):
    off, N = 0, len(code)
    while off < N:
        adv = False
        for i in md.disasm(code[off:], base+off):
            yield i; off = i.address-base+i.size; adv = True
        if not adv: off += 4

# --- build xref index (1 lan quet) ---
print(f"=== find_getseed: {LIB} ===")
xref = defaultdict(list)
adrp = {}
code = raw[to0:to0+tsz]
for i in disasm_all(code, tv0):
    if i.id == ARM64_INS_ADRP and i.operands[1].type == ARM64_OP_IMM:
        adrp[i.operands[0].reg] = i.operands[1].imm
    elif i.id == ARM64_INS_ADD and len(i.operands)==3 and i.operands[2].type==ARM64_OP_IMM and i.operands[1].type==ARM64_OP_REG:
        r=i.operands[1].reg
        if r in adrp: xref[adrp[r]+i.operands[2].imm].append((i.address,"ADD"))
    elif i.id == ARM64_INS_LDR and i.operands[1].type==ARM64_OP_MEM:
        b=i.operands[1].mem.base
        if b in adrp: xref[adrp[b]+i.operands[1].mem.disp].append((i.address,"LDR"))

# --- tim strings ---
PATS = [rb"get_seed", rb"/ms/", rb"mssdk", rb"ms/get", rb"report", rb"attest",
        rb"nonce", rb"cert", rb"seed", rb"pipo", rb"integrity", rb"device_token",
        rb"tt_info", rb"metasec", rb"/v[0-9]/", rb"webcast", rb"passport"]
seen=set()
def va_of(off):
    return off  # va==off vung thap
print("\n[strings + xref]")
for pat in PATS:
    for mobj in re.finditer(pat, raw):
        i = mobj.start()
        lo=i
        while lo>0 and 32<=raw[lo-1]<127: lo-=1
        hi=i
        while hi<len(raw) and 32<=raw[hi]<127: hi+=1
        if lo in seen: continue
        seen.add(lo)
        s = raw[lo:hi].decode("latin1","replace")
        if len(s) < 3 or len(s) > 90: continue
        va = va_of(lo)
        xr = xref.get(va, [])
        if xr:  # chi in string CO xref (dang duoc code dung)
            disp = s if len(s)<=60 else s[:57]+"..."
            print(f"  0x{va:x} {disp!r:64s} <- " + ", ".join(f"0x{a:x}" for a,_ in xr[:5]))
