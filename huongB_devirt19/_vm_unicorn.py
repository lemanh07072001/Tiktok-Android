#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn.py — Unicorn harness for the slot16 VM builder at 0x55950.
#
# Strategy: emulate the VM function in Unicorn. The VM is a pure interpreter
# (0 direct BL calls). We hook SM3 @0xa0748 and other callouts, feed the VM
# state captured from the phone, and let it run to produce slot16.
#
# Phase 1: load .so, set up basic emulation, run the VM function entry.
# Phase 2: identify what callouts the VM makes and hook them.
# Phase 3: capture initial VM state from phone, replay here.
#
# Run: python _vm_unicorn.py
import os, sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_REG_X23, ARM64_REG_X17, ARM64_OP_REG, ARM64_OP_IMM

os.chdir(os.path.dirname(os.path.abspath(__file__)))

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL
    from unicorn.arm64_const import *
    # UC_HOOK_MEM_UNMAPPED may not exist in all versions
    try:
        from unicorn import UC_HOOK_MEM_UNMAPPED
    except ImportError:
        UC_HOOK_MEM_UNMAPPED = 0x10  # fallback
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False
    print("[!] unicorn not installed — pip install unicorn")
    print("    Running in analysis-only mode.")

SO = "bin/libmetasec_ov.so"
VM_ENTRY = 0x55950
SM3_FN = 0xa0748
MD5_FN = 0x15b594
LOAD_BASE = 0x400000  # typical Android .so base
STACK_BASE = 0x80000000
STACK_SIZE = 0x100000  # 1MB

# ── Known callout addresses (ARM64 functions the VM might call) ──
CALLOUTS = {
    # crypto
    0xa0748: "SM3_compress",
    0x15b594: "MD5",
    # memory
    # (memcpy, memset are typically PLT-resolved)
    # string
    # (std::string ops)
}


def load_so():
    with open(SO, "rb") as f:
        return f.read()


def find_plt_entries(so):
    """Find PLT entries for common functions."""
    # PLT is typically at .plt section
    # Each PLT entry is 16 bytes (3 instructions)
    # We can use the .rela.plt to find names
    import re
    # Parse .dynstr for function names
    dynstr_off = 0x39c0
    dynstr_size = 0x143e
    dynstr = so[dynstr_off:dynstr_off + dynstr_size]

    # Parse .rela.plt for relocations
    rela_plt_off = 0x2f418
    rela_plt_size = 0xf78
    rela_plt = so[rela_plt_off:rela_plt_off + rela_plt_size]

    # Parse .dynsym for symbol indices
    dynsym_off = 0xdf8
    dynsym_size = 0x2bc8
    dynsym = so[dynsym_off:dynsym_off + dynsym_size]

    # Parse .plt section
    plt_off = 0x30390
    plt_size = 0xa70

    entries = {}
    for i in range(0, rela_plt_size, 24):  # RELA entries are 24 bytes
        r_offset = struct.unpack_from("<Q", rela_plt, i)[0]
        r_info = struct.unpack_from("<Q", rela_plt, i + 8)[0]
        r_addend = struct.unpack_from("<q", rela_plt, i + 16)[0]

        sym_idx = r_info >> 32
        # Read symbol name
        sym_off = dynsym_off + sym_idx * 24  # ELF64 sym = 24 bytes
        if sym_off + 8 > len(so):
            continue
        st_name = struct.unpack_from("<I", so, sym_off)[0]
        if st_name > 0 and st_name < dynstr_size:
            name = dynstr[st_name:].split(b'\0')[0].decode('latin1', errors='replace')
            # Calculate PLT entry address (each PLT entry is 16 bytes)
            if i // 24 < plt_size // 16:
                plt_addr = plt_off + (i // 24) * 16
                entries[name] = plt_addr
                entries[plt_addr] = name

    return entries


def analyze_vm_structure(so):
    """Analyze the VM function to understand its structure."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Find function end (next function prologue after VM)
    end = VM_ENTRY + 0x8000  # scan up to 32KB
    for off in range(VM_ENTRY + 0x100, VM_ENTRY + 0x8000, 4):
        insns = list(md.disasm(so[off:off + 4], off))
        if not insns:
            continue
        i = insns[0]
        if i.mnemonic == "ret" and off > VM_ENTRY + 0x1000:
            end = off + 4
            break
        if i.mnemonic == "stp" and off > VM_ENTRY + 0x5000:
            regs = set()
            for op in i.operands:
                if op.type == ARM64_OP_REG:
                    regs.add(op.reg)
            if 29 in regs and 30 in regs:  # x29, x30 = next function
                end = off
                break

    size = end - VM_ENTRY
    print(f"=== VM function: 0x{VM_ENTRY:x} - 0x{end:x} ({size} bytes) ===")

    # Disassemble
    insns = list(md.disasm(so[VM_ENTRY:VM_ENTRY + size], VM_ENTRY))

    # Find all BR instructions (indirect jumps = dispatch + callouts)
    br_insns = [i for i in insns if i.mnemonic == "br"]
    print(f"\nBR (indirect jump) sites: {len(br_insns)}")
    for i in br_insns[:10]:
        reg = i.op_str.strip()
        print(f"  0x{i.address:x}: br {reg}")

    # Find all BLR instructions (indirect calls = external callouts)
    blr_insns = [i for i in insns if i.mnemonic == "blr"]
    print(f"\nBLR (indirect call) sites: {len(blr_insns)}")
    for i in blr_insns:
        reg = i.op_str.strip()
        print(f"  0x{i.address:x}: blr {reg}")

    # Find x17 references (likely the dispatch register)
    x17_ldr = [i for i in insns if i.mnemonic == "ldr" and
               any(op.type == ARM64_OP_REG and op.reg == ARM64_REG_X17 for op in i.operands)]
    print(f"\nLDR x17 (dispatch reg) sites: {len(x17_ldr)}")
    for i in x17_ldr[:10]:
        print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")

    return insns, end


def build_unicorn_harness(so):
    """Build a Unicorn emulation harness for the VM."""
    if not HAS_UNICORN:
        print("\n[!] Skipping Unicorn harness — unicorn not installed.")
        print("    pip install unicorn")
        return

    print("\n=== Building Unicorn harness ===")

    # Initialize Unicorn
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map .so at LOAD_BASE
    so_size = len(so)
    # Round up to page boundary
    mapped_size = ((so_size + 0xfff) // 0x1000) * 0x1000
    uc.mem_map(LOAD_BASE, mapped_size, UC_PROT_ALL)
    uc.mem_write(LOAD_BASE, so)

    # Map stack
    uc.mem_map(STACK_BASE - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
    sp = STACK_BASE - 0x1000  # initial SP

    # ── Set up initial register state ──
    # We need to know the initial state. For now, use placeholder values.
    # The real state comes from phone capture.

    # x23 = pointer to VM bytecode pointer (ptr-to-ptr)
    # We'll set this up once we know the bytecode location
    # For now, set up the VM entry point registers
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X29, sp)  # frame pointer = sp initially
    # x30 = link register (return address) — set to a sentinel
    uc.reg_write(UC_ARM64_REG_X30, 0xDEAD0000)

    # Hook memory access for unmapped regions
    def hook_mem_unmapped(uc, access, address, size, value, user_data):
        print(f"[MEM UNMAPPED] access={access} addr=0x{address:x} size={size}")
        return False  # let it crash

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)

    # Hook all memory writes to track state changes
    def hook_mem_write(uc, access, address, size, value, user_data):
        # Track writes to the VM register file (x24 area)
        pass

    # Hook the SM3 function
    def hook_sm3(uc, address, size, user_data):
        print(f"[SM3] called at 0x{address:x}")
        # SM3 compression function: state at [x0+8..+0x28], input 64B at x1
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        print(f"  x0=0x{x0:x} x1=0x{x1:x}")
        # Read the 64-byte input block
        block = uc.mem_read(x1, 64)
        print(f"  block[0:32]={block[:32].hex()}")

    # Hook the MD5 function
    def hook_md5(uc, address, size, user_data):
        print(f"[MD5] called at 0x{address:x}")

    # Hook code at SM3 entry
    uc.hook_add(UC_HOOK_CODE, hook_sm3, begin=LOAD_BASE + SM3_FN, end=LOAD_BASE + SM3_FN)

    # Hook code at MD5 entry
    uc.hook_add(UC_HOOK_CODE, hook_md5, begin=LOAD_BASE + MD5_FN, end=LOAD_BASE + MD5_FN)

    print("[*] Unicorn harness ready.")
    print(f"    .so mapped at 0x{LOAD_BASE:x} ({mapped_size//1024}KB)")
    print(f"    stack at 0x{STACK_BASE - STACK_SIZE:x} - 0x{STACK_BASE:x}")
    print(f"    SM3 hook at 0x{LOAD_BASE + SM3_FN:x}")
    print(f"    MD5 hook at 0x{LOAD_BASE + MD5_FN:x}")
    print()
    print("[*] Next: capture VM state from phone (frida hook at 0x55950)")
    print("    then feed state into uc.reg_write() and uc.emu_start()")

    return uc


def main():
    so = load_so()
    print(f"[*] Loaded {SO} ({len(so)} bytes)")

    # Find PLT entries
    plt = find_plt_entries(so)
    print(f"\n[*] PLT entries: {len(plt)} total")
    for name, addr in sorted(plt.items(), key=lambda x: x[1] if isinstance(x[1], int) else 0):
        if isinstance(addr, int):
            print(f"    {name}: 0x{addr:x}")

    # Analyze VM structure
    insns, end = analyze_vm_structure(so)

    # Build Unicorn harness
    uc = build_unicorn_harness(so)

    print("\n=== VM Structure Summary ===")
    print(f"  VM interpreter: 0x{VM_ENTRY:x} - 0x{end:x} ({end - VM_ENTRY} bytes)")
    print(f"  Instructions: {len(insns)}")
    br_count = sum(1 for i in insns if i.mnemonic == "br")
    blr_count = sum(1 for i in insns if i.mnemonic == "blr")
    print(f"  BR (dispatch): {br_count}")
    print(f"  BLR (callouts): {blr_count}")
    print(f"  Architecture: custom VM, 64-opcode jump table, self-modifying bytecode")
    print(f"  VM PC: x23 (ptr-to-ptr)")
    print(f"  VM regfile: x24 (32 x 8-byte slots)")
    print(f"  Opcode table: x30 (= 0x52924, inline code snippets)")
    print(f"  Data table: x7 (= 0x1f0000, .data section)")


if __name__ == "__main__":
    main()