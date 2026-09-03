#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""find_jni.py v2 — Quet JNINativeMethod ap R_AARCH64_RELATIVE reloc + disasm JNI_OnLoad."""
import sys, struct
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_OP_IMM, ARM64_OP_REG, ARM64_INS_BL, ARM64_INS_BLR

LIB = sys.argv[1]
bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()
segs = [(s.virtual_address, s.file_offset, s.physical_size)
        for s in bin_.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
secs = {s.name: (s.virtual_address, s.offset, s.size) for s in bin_.sections if s.size}

def va_to_off(va):
    for v, o, sz in segs:
        if v <= va < v + sz: return o + (va - v)
    return None

# ---- reloc map: vaddr slot -> resolved pointer value ----
relmap = {}
for r in bin_.relocations:
    try:
        add = r.addend
    except Exception:
        add = 0
    if add:
        relmap[r.address] = add
print(f"[reloc] {len(relmap)} slot co addend (RELATIVE)")

def ptr_at(slot_va):
    if slot_va in relmap:
        return relmap[slot_va]
    o = va_to_off(slot_va)
    if o is None: return 0
    return struct.unpack_from("<Q", raw, o)[0]

def cstr(va, maxlen=96):
    o = va_to_off(va)
    if o is None: return None
    end = raw.find(b"\x00", o, o + maxlen)
    if end < 0: return None
    b = raw[o:end]
    if b and all(32 <= c < 127 for c in b):
        return b.decode("ascii")
    return None

tv0, _, tsz = secs[".text"]
def looks_code(va): return tv0 <= va < tv0 + tsz
def looks_sig(s): return s is not None and s.startswith("(") and ")" in s

cands = []
for sec in (".data.rel.ro", ".data", ".data.rel"):
    if sec not in secs: continue
    v0, o0, sz = secs[sec]
    for i in range(0, sz - 24, 8):
        slot = v0 + i
        p0, p1, p2 = ptr_at(slot), ptr_at(slot+8), ptr_at(slot+16)
        name, sig = cstr(p0, 64), cstr(p1, 64)
        if name and looks_sig(sig) and looks_code(p2):
            cands.append((slot, name, sig, p2))

print(f"\n=== JNINativeMethod entries: {len(cands)} ===")
for slot, name, sig, fn in cands:
    print(f"  @0x{slot:x}  name={name!r:14s} sig={sig!r:40s} fn=0x{fn:x}")

# ---- disasm JNI_OnLoad de tim methods-table pointer + RegisterNatives ----
JOL = 0x4dda0
print(f"\n=== Disasm JNI_OnLoad @ 0x{JOL:x} (tim ADRP+ADD toi bang methods) ===")
o = va_to_off(JOL)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
adrp = {}
cnt = 0
for insn in md.disasm(raw[o:o+200*4], JOL):
    if insn.id == ARM64_INS_ADRP:
        adrp[insn.operands[0].reg] = insn.operands[1].imm
    elif insn.id == ARM64_INS_ADD and len(insn.operands)==3 and insn.operands[2].type==ARM64_OP_IMM:
        src = insn.operands[1].reg
        if src in adrp:
            tgt = adrp[src] + insn.operands[2].imm
            nm = cstr(tgt, 48)
            extra = f"  -> &data 0x{tgt:x}" + (f"  cstr={nm!r}" if nm else "")
            print(f"  0x{insn.address:08x}: {insn.mnemonic:6s} {insn.op_str}{extra}")
            cnt += 1
            continue
    # in cac call
    if insn.id in (ARM64_INS_BL, ARM64_INS_BLR):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:6s} {insn.op_str}   <call>")
    if insn.mnemonic == "ret":
        print(f"  0x{insn.address:08x}: ret"); break
