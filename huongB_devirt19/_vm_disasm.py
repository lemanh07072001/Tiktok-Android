#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_disasm.py — deep disasm of the slot16 VM builder at 0x55950 in libmetasec_ov.so.
# Run: python _vm_disasm.py > vm_disasm.txt   (redirect to avoid cp1252 issues)
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_REG_X23, ARM64_OP_REG, ARM64_OP_IMM

SO = "bin/libmetasec_ov.so"
VM_ENTRY = 0x55950
MAX_SCAN = 0x8000  # 32KB — metasec VM functions can be huge

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))


def load_so():
    with open(SO, "rb") as f:
        return f.read()


def find_function_boundaries(code, entry):
    """Find approximate function end."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for offset in range(entry + 0x100, entry + MAX_SCAN, 4):
        insns = list(md.disasm(code[offset:offset + 4], offset))
        if not insns:
            continue
        i = insns[0]
        if i.mnemonic == "ret" and offset > entry + 0x200:
            return offset + 4
        if i.mnemonic == "stp" and offset > entry + 0x1000:
            regs = set()
            for op in i.operands:
                if op.type == ARM64_OP_REG:
                    regs.add(op.reg)
            if 29 in regs and 30 in regs:
                return offset
    return entry + MAX_SCAN


def disasm_range(code, base, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(code[base:base + size], base))


def analyze_vm():
    so = load_so()
    end = find_function_boundaries(so, VM_ENTRY)
    size = min(end - VM_ENTRY, MAX_SCAN)
    print(f"=== VM function: 0x{VM_ENTRY:x} - 0x{end:x} ({size} bytes, {size//4} insns) ===")

    insns = disasm_range(so, VM_ENTRY, size)

    # ── Phase 1: structural scan ──
    bl_count = 0
    br_count = 0
    ret_count = 0
    indirect_br = 0
    x23_refs = 0
    adr_adrp = 0
    eor_xor = 0
    mem_ops = 0
    b_lo_targets = {}
    all_br_targets = []

    for i in insns:
        if i.mnemonic == "bl":
            bl_count += 1
        elif i.mnemonic in ("br", "blr"):
            br_count += 1
            if i.mnemonic == "br":
                indirect_br += 1
        elif i.mnemonic == "ret":
            ret_count += 1
        elif i.mnemonic in ("adr", "adrp"):
            adr_adrp += 1
        elif i.mnemonic == "eor":
            eor_xor += 1

        # x23 refs via capstone const
        for op in i.operands:
            if op.type == ARM64_OP_REG and op.reg == ARM64_REG_X23:
                x23_refs += 1

        if i.mnemonic in ("ldr", "ldrb", "ldrh", "ldur", "ldursw", "str", "strb", "strh", "stur"):
            mem_ops += 1

        if i.mnemonic == "b.lo":
            target = i.operands[0].imm
            b_lo_targets[target] = b_lo_targets.get(target, 0) + 1

        # Collect all indirect branch targets
        if i.mnemonic == "br":
            all_br_targets.append(i)

    print(f"\n[structure] {len(insns)} instructions")
    print(f"  BL (direct calls): {bl_count}  (0 = pure VM)")
    print(f"  BR (indirect jumps): {indirect_br}")
    print(f"  RET: {ret_count}")
    print(f"  ADR/ADRP: {adr_adrp}")
    print(f"  EOR: {eor_xor}")
    print(f"  MEM ops: {mem_ops}")
    print(f"  x23 refs: {x23_refs}  (VM PC)")

    # ── Phase 2: dispatch analysis ──
    if b_lo_targets:
        dispatch_header = max(b_lo_targets, key=b_lo_targets.get)
        print(f"\n[dispatch] most-frequent b.lo target: 0x{dispatch_header:x} ({b_lo_targets[dispatch_header]}x)")
        dispatch_sites = [i for i in insns if i.mnemonic == "b.lo" and i.operands[0].imm == dispatch_header]
        print(f"  dispatch sites: {len(dispatch_sites)}")

    # ── Phase 3: ADRP table references ──
    adrp_sites = [i for i in insns if i.mnemonic == "adrp"]
    print(f"\n[opcode table] ADRP sites: {len(adrp_sites)}")
    for i in adrp_sites[:15]:
        dst = i.operands[0].reg
        page = i.operands[1].imm
        # Find next ADD with same dest reg
        for j in insns:
            if j.address > i.address and j.mnemonic == "add":
                ops = j.operands
                if len(ops) >= 3 and ops[1].type == ARM64_OP_REG and ops[1].reg == dst:
                    off = ops[2].imm if ops[2].type == ARM64_OP_IMM else 0
                    table_addr = page + off
                    print(f"  0x{i.address:x}: ADRP x{dst}, #0x{page:x} ; +ADD -> table 0x{table_addr:x}")
                    break

    # ── Phase 4: x23 PC pattern ──
    if x23_refs > 0:
        print(f"\n[VM PC] x23 pattern (first 20):")
        x23_insns = [i for i in insns if any(op.type == ARM64_OP_REG and op.reg == ARM64_REG_X23 for op in i.operands)]
        for i in x23_insns[:20]:
            print(f"  0x{i.address:x}: {i.mnemonic:8s} {i.op_str}")

    # ── Phase 5: full disasm to file ──
    outpath = "vm_disasm_full.txt"
    with open(outpath, "w") as f:
        f.write(f"=== VM function 0x{VM_ENTRY:x} - 0x{VM_ENTRY+size:x} ({size} bytes) ===\n\n")
        for i in insns:
            f.write(f"0x{i.address:x}: {i.mnemonic:8s} {i.op_str}\n")
    print(f"\n[output] full disasm -> {outpath}")

    return insns, so


if __name__ == "__main__":
    analyze_vm()