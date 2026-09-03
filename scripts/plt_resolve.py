#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plt_resolve.py — Map PLT stub -> ten symbol ngoai, resolve cac BL target."""
import sys
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import (ARM64_OP_IMM, ARM64_OP_MEM, ARM64_INS_ADRP,
                            ARM64_INS_LDR, ARM64_OP_REG)

LIB = sys.argv[1]
# BL target quan tam trong dispatcher 0x11c2ec
TARGETS = [int(x, 16) for x in sys.argv[2:]] if len(sys.argv) > 2 else \
          [0x30be0, 0x30a10, 0x30930, 0x30630, 0x30d50, 0x304c0, 0x30dd0, 0x16e9c8, 0x16e9c8]

bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()
secs = {s.name: (s.virtual_address, s.offset, s.size) for s in bin_.sections if s.size}

# GOT vaddr -> symbol name (tu JUMP_SLOT relocations)
got_sym = {}
for r in bin_.relocations:
    try:
        nm = r.symbol.name if r.has_symbol else None
    except Exception:
        nm = None
    if nm:
        got_sym[r.address] = nm
print(f"[reloc] {len(got_sym)} JUMP_SLOT/GOT symbol")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

def read_at(va, n=16):
    for s in bin_.sections:
        if s.virtual_address <= va < s.virtual_address + s.size and s.name in (".plt", ".text"):
            off = s.offset + (va - s.virtual_address)
            return raw[off:off+n]
    # fallback: va==off cho vung thap
    return raw[va:va+n]

def plt_stub_symbol(stub_va):
    """Disasm 1 PLT stub -> GOT vaddr -> symbol."""
    code = read_at(stub_va, 16)
    page = None
    for insn in md.disasm(code, stub_va):
        if insn.id == ARM64_INS_ADRP:
            page = insn.operands[1].imm
        elif insn.id == ARM64_INS_LDR and page is not None:
            m = insn.operands[1]
            if m.type == ARM64_OP_MEM:
                got_va = page + m.mem.disp
                return got_sym.get(got_va), got_va
    return None, None

plt = secs.get(".plt")
print(f"[.plt] {('vaddr=0x%x off=0x%x size=0x%x' % plt) if plt else 'khong co'}")
print("\n[Resolve BL targets tu dispatcher]")
for t in dict.fromkeys(TARGETS):
    nm, got = plt_stub_symbol(t)
    if nm:
        print(f"    bl 0x{t:x} -> PLT -> {nm}()   (GOT 0x{got:x})")
    else:
        zone = "trong .plt?" if plt and plt[0] <= t < plt[0]+plt[2] else "trong .text (ham noi bo)"
        print(f"    bl 0x{t:x} -> {zone} (khong phai PLT-JUMP_SLOT)")
