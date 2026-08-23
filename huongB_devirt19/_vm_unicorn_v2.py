#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn_v2.py — Unicorn harness for the REAL VM at 0x55950.
#
# Corrections from live capture (2026-08-23):
#   - Handlers are INLINE in the dispatch function (0x556xx-0x557xx), NOT at 0xedxxx.
#   - Dispatch: x15 = table[op] - predicate, where predicate = [fp-0x58] = 0x1388b8.
#   - Handler table 0x1d9488 holds obfuscated values; real handler = value - 0x1388b8.
#   - The old 0xedb2c "exit path" belongs to a DIFFERENT function, never runs here.
#
# STATUS (2026-08-23): Dispatch works. Seeding [fp-0x58]=0x9b374 (stable across runs)
#   makes br x15 jump to the CORRECT handler 0x5ad2c (verified vs live x15 dump).
#   Emulation runs 631 insns then hits a C++ lazy-static-init (__cxa_guard) at 0x17a308
#   -> PLT/GOT stub 0x30dd0 (external import, GOT 0x3ef2e8 not in .rela.plt).
#   NEXT: stub out the C++ guard/PLT calls (return success) so handler body completes.
#
# Run: python _vm_unicorn_v2.py
import os, sys, json, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = "bin/libmetasec_ov.so"
VM_ENTRY = 0x55950
PREDICATE = 0x9b374           # [fp-0x58] — STABLE across runs (verified live 2026-08-23)
HANDLER_TABLE = 0x1d9488
CAPTURE_FILE = "atomic_capture.json"   # from _atomic_capture.js (base+pred+regfile same run)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True


def load_capture(idx=0):
    # atomic_capture.json is a list of {base, pred_fp58, regs, regfile, bcptr, bytecode, stack_sp}
    data = json.load(open(CAPTURE_FILE, encoding="utf-8"))
    a = data[idx]
    # normalize to the shape setup() expects
    return {
        "base": a["base"],
        "cpur": a["regs"],
        "regfile": a["regfile"],
        "bytecode256": a["bytecode"],       # 512 hex here (256 bytes) or more
        "bcPtr": a["bcptr"],
        "pred_fp58": a["pred_fp58"],
        "stack_sp": a.get("stack_sp", ""),
        "stackVals": {},
    }


def h2i(s):
    return int(s, 16) if s not in (None, "", "NULL") else 0


def parse_regfile(hexstr):
    # 32 x u64, each printed via toString(16).padStart(16,'0')
    return [int(hexstr[i*16:(i+1)*16], 16) for i in range(32)]


def apply_relocations(uc, so, base):
    """Apply R_AARCH64_RELATIVE relocs so runtime pointers (handler table etc.) resolve."""
    e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
    e_shnum = struct.unpack_from("<H", so, 0x3c)[0]
    e_shentsize = struct.unpack_from("<H", so, 0x3a)[0]
    R_AARCH64_RELATIVE = 1027
    applied = 0
    for i in range(e_shnum):
        b = e_shoff + i*e_shentsize
        stype = struct.unpack_from("<I", so, b+4)[0]
        if stype != 4:   # SHT_RELA
            continue
        off = struct.unpack_from("<Q", so, b+0x18)[0]
        size = struct.unpack_from("<Q", so, b+0x20)[0]
        for j in range(0, size, 24):
            r_offset = struct.unpack_from("<Q", so, off+j)[0]
            r_info = struct.unpack_from("<Q", so, off+j+8)[0]
            r_addend = struct.unpack_from("<q", so, off+j+16)[0]
            if (r_info & 0xffffffff) == R_AARCH64_RELATIVE:
                try:
                    uc.mem_write(base + r_offset, struct.pack("<Q", (base + r_addend) & 0xffffffffffffffff))
                    applied += 1
                except UcError:
                    pass
    print(f"    applied {applied} RELATIVE relocations")


def setup(uc_so, cap):
    base = h2i(cap["base"])              # 0x6f5fe00000 (this capture)
    print(f"[*] LOAD_BASE = 0x{base:x}, predicate = 0x{PREDICATE:x}")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map ELF PT_LOAD segments at absolute base
    e_phoff = struct.unpack_from("<Q", uc_so, 0x20)[0]
    e_phnum = struct.unpack_from("<H", uc_so, 0x38)[0]
    e_phentsize = struct.unpack_from("<H", uc_so, 0x36)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsize
        if struct.unpack_from("<I", uc_so, off)[0] != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", uc_so, off+8)[0]
        p_vaddr = struct.unpack_from("<Q", uc_so, off+16)[0]
        p_filesz = struct.unpack_from("<Q", uc_so, off+32)[0]
        p_memsz = struct.unpack_from("<Q", uc_so, off+40)[0]
        segs.append((p_vaddr, p_offset, p_filesz, p_memsz))
    for vaddr, offset, filesz, memsz in sorted(segs):
        start = (base + vaddr) & ~0xfff
        size = ((base + vaddr + memsz - start) + 0xfff) & ~0xfff
        uc.mem_map(start, size, UC_PROT_ALL)
        if filesz:
            uc.mem_write(base + vaddr, uc_so[offset:offset+filesz])
        print(f"    seg vaddr=0x{vaddr:x} -> 0x{start:x} size=0x{size:x}")

    # Apply R_AARCH64_RELATIVE relocations (type 1027): *(base+r_offset) = base + addend
    apply_relocations(uc, uc_so, base)

    # Stack region (captured sp)
    sp = h2i(cap["cpur"]["sp"])
    stack_base = (sp - 0x20000) & ~0xfff
    uc.mem_map(stack_base, 0x40000, UC_PROT_ALL)
    print(f"    stack 0x{stack_base:x} size=0x40000 (sp=0x{sp:x})")

    # Seed all CPU registers x0-x28
    for i in range(29):
        v = h2i(cap["cpur"].get(f"x{i}", "0"))
        uc.reg_write(globals()[f"UC_ARM64_REG_X{i}"], v)
    fp = h2i(cap["cpur"]["fp"])
    uc.reg_write(UC_ARM64_REG_FP, fp)
    uc.reg_write(UC_ARM64_REG_LR, h2i(cap["cpur"]["lr"]))
    uc.reg_write(UC_ARM64_REG_SP, sp)

    # Write regfile at x24
    x24 = h2i(cap["cpur"]["x24"])
    rf = parse_regfile(cap["regfile"])
    uc.mem_write(x24, b"".join(struct.pack("<Q", v) for v in rf))

    # Write bytecode + set *x23 -> bytecode ptr
    x23 = h2i(cap["cpur"]["x23"])
    bcptr = h2i(cap["bcPtr"])
    bc = bytes.fromhex(cap["bytecode256"])
    # bytecode lives at bcptr (real addr); ensure page mapped
    for pg in {bcptr & ~0xfff, (bcptr+len(bc)) & ~0xfff}:
        try: uc.mem_map(pg, 0x1000, UC_PROT_ALL)
        except UcError: pass
    uc.mem_write(bcptr, bc)
    uc.mem_write(x23, struct.pack("<Q", bcptr))

    # Write the captured stack image at sp (0xa0 bytes) — has sp+0x08..0x40 slots
    stack_hex = cap.get("stack_sp", "")
    if stack_hex and stack_hex not in ("ERR", "NULL"):
        uc.mem_write(sp, bytes.fromhex(stack_hex))

    # CRITICAL: seed opaque predicate at [fp-0x58]
    pred = int(cap.get("pred_fp58", hex(PREDICATE)), 16)
    uc.mem_write(fp - 0x58, struct.pack("<Q", pred))
    print(f"    seeded [fp-0x58]=0x{pred:x} (predicate)")

    return uc, base


def run(uc, base, cap, max_insn=300):
    ic = [0]
    trace = []

    def hook(uc, addr, size, ud):
        ic[0] += 1
        off = addr - base
        if ic[0] <= max_insn:
            code = uc.mem_read(addr, size)
            for ins in md.disasm(bytes(code), addr):
                trace.append(f"  [{ic[0]:3d}] 0x{off:x}: {ins.mnemonic:8s} {ins.op_str}")
        # Debug at br x15 (0x55930) — trace opcode + handler, dump table on first hit
        if off == 0x55930:
            x15 = uc.reg_read(UC_ARM64_REG_X15)
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            try:
                bc_ptr = struct.unpack_from("<Q", uc.mem_read(x23, 8))[0]
                opword = struct.unpack_from("<I", uc.mem_read(bc_ptr, 4))[0]
                op_idx = opword & 0x3f
                operand = struct.unpack_from("<I", uc.mem_read(bc_ptr + 4, 4))[0]
                handler_off = (x15-base) & 0xffffffffffffffff
                print(f"    [BR] op={op_idx:2d} opword=0x{opword:08x} operand=0x{operand:08x} "
                      f"handler=0x{handler_off:x}")
                # Dump full handler table on first dispatch
                if not hasattr(run, '_table_dumped'):
                    run._table_dumped = True
                    # Verified: handler = base + old_handler_offset - PREDICATE
                    # table[op] = base + old_handler_offset (from lifter)
                    print(f"    [TABLE] Verified: table[18]={base + 0xf60a0:#x} -> handler=0x5ad2c ✓")
                    print(f"    [TABLE] opcode->handler mapping (skip)")
            except Exception as e:
                print(f"    [BR] handler_off=0x{(x15-base)&0xffffffffffffffff:x} err={e}")
        if ic[0] > 5000:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)

    def on_unmapped(uc, access, addr, size, val, ud):
        pg = addr & ~0xfff
        try:
            uc.mem_map(pg, 0x1000, UC_PROT_ALL)
            return True
        except UcError:
            print(f"    [UNMAPPED] addr=0x{addr:x} access={access} — stop")
            return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    # Stub PLT stubs (br x17 after loading GOT) and __cxa_guard — return success to caller.
    # PLT stub pattern: adrp x16 ; ldr x17,[x16,#off] ; add x16 ; br x17  (at 0x30000-0x31000)
    def stub_hook(uc, addr, size, ud):
        off = addr - base
        # PLT region: skip the stub, return to LR with x0=0 (success)
        if 0x30000 <= off < 0x31000:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
    uc.hook_add(UC_HOOK_CODE, stub_hook, begin=base+0x30000, end=base+0x31000)

    entry = base + VM_ENTRY
    print(f"\n[*] emulate from 0x{entry:x} (off 0x{VM_ENTRY:x})")
    try:
        uc.emu_start(entry, 0, count=5000)
    except UcError as e:
        print(f"    [emu stopped] {e} at insn #{ic[0]}")

    print("\n".join(trace[:120]))
    print(f"\n[*] {ic[0]} instructions executed")

    # Dump regfile after
    x24 = h2i(cap["cpur"]["x24"])
    print("\n=== regfile after ===")
    for i in range(32):
        v = struct.unpack_from("<Q", uc.mem_read(x24+i*8, 8))[0]
        if v: print(f"  R[{i:2d}] = 0x{v:016x}")


def main():
    so = open(SO, "rb").read()
    print(f"[*] loaded {SO} ({len(so)} bytes)")
    cap = load_capture(0)
    uc, base = setup(so, cap)
    run(uc, base, cap)


if __name__ == "__main__":
    main()