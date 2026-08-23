#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn_replay.py — Unicorn harness for VM replay using captured phone state.
#
# Feeds the captured VM entry state (from _vm_entry_capture.js) into Unicorn
# and emulates the VM to produce slot16. This is the Branch B endgame.
#
# Run: python _vm_unicorn_replay.py
import os, sys, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm64_const import *

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = "bin/libmetasec_ov.so"
LOAD_BASE = 0x6f5fe00000  # From the capture: lr=0x6f5fe55950, base=lr-0x55950
VM_ENTRY = 0x55950

# Captured VM entry state (from frida, call #1)
CAPTURED_STATE = {
    "x0": 0x0,
    "x1": 0x1,
    "x2": 0x70e6c592d0,
    "x3": 0x962c02a0,
    "x4": 0x6f276e8e40,
    "x5": 0x6f5fe76e5c,
    "x6": 0x6f5ff7c880,
    "x7": 0x6f5fff0000,  # = LOAD_BASE + 0x1f0000 (.data)
    "x8": 0x0,
    "x23": 0x6f276e91e0,  # ptr to bytecode ptr on stack
    "x24": 0x6f276e91e8,  # ptr to register file on stack
    "fp": 0x6f276e8e20,
    "lr": 0x6f5fe55950,   # return address
    "sp": 0x6f276e8d40,
}

# Captured bytecode (256 bytes, same for all 5 calls)
BYTECODE_HEX = (
    "6c953f00ac08aa24ac082a0de6024a83920002002a8060e92a804eec2a406eed2a0062e92c043300"
    "6c953f000f175087ac086a8cac08020da6426483920002002a804ced2a4042e92c1409002c240b00"
    "2c0433006c953f000f175887ac08020d920604ab2a4084e8920002002a804ced2a4042e92c140900"
    "2c240b002c0433006c953f00ac08ea0c2a4042e892060288ac086a082a0042e892060287ac086a08"
    "2ac022e89206028bac086a082a8022e89206028cac086a082a4022e89206028dac086a082a0002e8"
    "9206028eac086a082a8062e8920602ab2a0082e80f17408bac08020d2a4062e8260142832a0062e8"
    "26416e83664242832ac042e80f17488b"
)

# Captured register file (32 x 8 bytes, from call #1)
REGFILE_HEX = (
    "00000000000000000000006f5fe766280000006f608e06480000006f276e90800000006f5fe76e68"
    "0000006f276e91680000006f5ffda1a00000006f5fe76e5c0000006f5fe7a6b800000000000000c5"
    "0000006f276e9c8000000071f6cf18b0000000000000001a0000006f276e927000000073116ce540"
    "000000000000001a0000006f5fe76e5c0000006f608e06680000006f608e06580000006f608e0718"
    "0000006f60a59b20ffffffffff59682000000070e6c592b80000006f276e934800000073116d8abc"
    "0000006f5fe76e5c00000073116d89400000006f276e932000000073116d43000000006f276e8ff0"
    "ffffffffff5900000000006f5ff7c938"
)


def load_so():
    with open(SO, "rb") as f:
        return f.read()


def setup_unicorn(so):
    """Set up Unicorn with the .so and captured state, using proper ELF segment mapping."""
    print("[*] Setting up Unicorn...")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Parse ELF program headers and map segments properly
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phnum = struct.unpack_from("<H", so, 0x38)[0]
    e_phentsize = struct.unpack_from("<H", so, 0x36)[0]

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", so, off)[0]
        p_offset = struct.unpack_from("<Q", so, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", so, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", so, off + 32)[0]
        p_memsz = struct.unpack_from("<Q", so, off + 40)[0]
        p_flags = struct.unpack_from("<I", so, off + 4)[0]
        if p_type == 1:  # PT_LOAD
            segments.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

    # Sort by vaddr
    segments.sort()

    # Map each segment at BOTH vaddr and LOAD_BASE+vaddr
    # The code uses ADRP for absolute addresses and opaque predicates for vaddrs
    for vaddr, offset, filesz, memsz, flags in segments:
        page_mask = 0xfff
        for map_base in [0, LOAD_BASE]:  # vaddr mirror + absolute
            seg_start = map_base + vaddr
            seg_start_aligned = seg_start & ~page_mask
            page_off = seg_start - seg_start_aligned
            seg_size = ((page_off + memsz + page_mask) // 0x1000) * 0x1000
            uc_prot = UC_PROT_ALL
            if map_base == 0:
                print(f"  Mapping segment [vaddr mirror]: vaddr=0x{vaddr:x} -> 0x{seg_start_aligned:x} size=0x{seg_size:x}")
            else:
                print(f"  Mapping segment [absolute]: vaddr=0x{vaddr:x} -> 0x{seg_start_aligned:x} size=0x{seg_size:x}")
            uc.mem_map(seg_start_aligned, seg_size, uc_prot)
            if filesz > 0:
                uc.mem_write(seg_start, so[offset:offset + filesz])
            # BSS (memsz > filesz) is already zeroed by Unicorn

    so_size = len(so)
    mapped_so = ((so_size + 0xfff) // 0x1000) * 0x1000

    # Map stack area (captured sp is at 0x6f276e8d40)
    STACK_BASE = 0x6f276e0000
    STACK_SIZE = 0x20000  # 128KB
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)

    # Write captured bytecode to stack area (within mapped stack)
    # x23 = 0x6f276e91e0 points to a pointer to bytecode
    bytecode = bytes.fromhex(BYTECODE_HEX)
    bc_addr = 0x6f276ea000  # Place bytecode here (within stack mapping: 0x6f276e0000-0x6f27700000)
    uc.mem_write(bc_addr, bytecode)

    # Write the bytecode pointer at x23 (x23 is ptr-to-ptr)
    x23_val = CAPTURED_STATE["x23"]
    uc.mem_write(x23_val, struct.pack("<Q", bc_addr))

    # Write captured register file at x24
    x24_val = CAPTURED_STATE["x24"]
    # REGFILE_HEX is captured via readU64().toString(16) — hex of the u64 value
    # Parse as 32 x 16-char hex = 32 x 8 bytes big-endian
    regfile_raw = bytes.fromhex(REGFILE_HEX)
    # Convert to proper little-endian bytes for memory
    regfile_bytes = b''
    for i in range(32):
        val = int(REGFILE_HEX[i*16:(i+1)*16], 16)
        regfile_bytes += struct.pack("<Q", val)
    uc.mem_write(x24_val, regfile_bytes)

    # Write captured values at the addresses they point to
    # x5 = 0x6f5fe76e5c -> this is in the .so data section
    # x6 = 0x6f5ff7c880 -> this is also in .so
    # These are already mapped

    # Set registers
    for reg_name, reg_val in CAPTURED_STATE.items():
        if reg_name.startswith("x"):
            idx = int(reg_name[1:])
            uc.reg_write(getattr(sys.modules[__name__], f"UC_ARM64_REG_X{idx}"), reg_val)
        elif reg_name == "fp":
            uc.reg_write(UC_ARM64_REG_FP, reg_val)
        elif reg_name == "lr":
            uc.reg_write(UC_ARM64_REG_LR, reg_val)
        elif reg_name == "sp":
            uc.reg_write(UC_ARM64_REG_SP, reg_val)

    # Set VM working registers (x19-x22, x25-x28) from the captured register file
    # Parse register file values from the hex string
    regfile_vals = []
    for i in range(32):
        val = int(REGFILE_HEX[i*16:(i+1)*16], 16)
        regfile_vals.append(val)
    for i in range(32):
        if 19 <= i <= 22 or 25 <= i <= 28:
            reg_const = getattr(sys.modules[__name__], f"UC_ARM64_REG_X{i}")
            uc.reg_write(reg_const, regfile_vals[i])
    # Set x9-x18 to 0 (scratch registers)
    for i in range(9, 19):
        uc.reg_write(getattr(sys.modules[__name__], f"UC_ARM64_REG_X{i}"), 0)

    # Hook code execution to trace
    insn_count = [0]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    def hook_code(uc, address, size, user_data):
        insn_count[0] += 1
        if insn_count[0] <= 60:
            code = uc.mem_read(address, size)
            for i in md.disasm(bytes(code), address):
                print(f"  [{insn_count[0]:4d}] 0x{address:x}: {i.mnemonic:8s} {i.op_str}")

        # At the dispatch load (instruction 38), dump registers
        if insn_count[0] == 38:
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            x9 = uc.reg_read(UC_ARM64_REG_X9)
            x10 = uc.reg_read(UC_ARM64_REG_X10)
            x11 = uc.reg_read(UC_ARM64_REG_X11)
            x12 = uc.reg_read(UC_ARM64_REG_X12)
            x13 = uc.reg_read(UC_ARM64_REG_X13)
            x30 = uc.reg_read(UC_ARM64_REG_X30)
            x7 = uc.reg_read(UC_ARM64_REG_X7)
            print(f"  [DISPATCH] x7=0x{x7:x} x8=0x{x8:x} x9=0x{x9:x}")
            print(f"             x10=0x{x10:x} x11=0x{x11:x} x12=0x{x12:x} x13=0x{x13:x}")
            print(f"             x30=0x{x30:x}")
            dt_val = struct.unpack_from("<Q", uc.mem_read(x7 + 0xe0, 8))[0]
            print(f"             [x7+0xe0] = 0x{dt_val:016x}")

        # At the BR (instruction 49), dump x15 and x9
        if insn_count[0] == 49:
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            x9 = uc.reg_read(UC_ARM64_REG_X9)
            x15 = uc.reg_read(UC_ARM64_REG_X15)
            x29 = uc.reg_read(UC_ARM64_REG_X29)
            print(f"  [BR] x8=0x{x8:x} x9=0x{x9:x} x15=0x{x15:x} fp=0x{x29:x}")
            # Read the value at fp-0x58
            fp_minus_58 = struct.unpack_from("<Q", uc.mem_read(x29 - 0x58, 8))[0]
            print(f"       [fp-0x58] = 0x{fp_minus_58:016x}")

    # Hook code execution in both vaddr mirror and absolute ranges
    so_end = LOAD_BASE + max(vaddr + memsz for vaddr, _, _, memsz, _ in segments)
    vaddr_end = max(vaddr + memsz for vaddr, _, _, memsz, _ in segments)
    uc.hook_add(UC_HOOK_CODE, hook_code, begin=0, end=vaddr_end)
    uc.hook_add(UC_HOOK_CODE, hook_code, begin=LOAD_BASE, end=so_end)

    # Hook PLT stubs at vaddr (since VM dispatches to vaddrs)
    PLT_HOOKS = {
        0x30610: "getpid",
        0x30b40: "__cxa_finalize",
        0x309d0: "__cxa_atexit",
        0x30c10: "puts",
        0x30590: "sigemptyset",
        0x30760: "strtod",
        0x30930: "fork",
        0x30b20: "sleep_for",
        0x30480: "rename",
        0x30850: "remove",
    }

    def hook_plt_getpid(uc, address, size, user_data):
        pid = 0x4e22  # musically PID
        print(f"  [PLT] getpid() -> {pid}")
        uc.reg_write(UC_ARM64_REG_X0, pid)
        # Skip the PLT stub: return to x30
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_plt_puts(uc, address, size, user_data):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        try:
            s = uc.mem_read(x0, 64).split(b'\0')[0].decode('latin1', errors='replace')
            print(f"  [PLT] puts(\"{s}\")")
        except Exception:
            print(f"  [PLT] puts(0x{x0:x})")
        uc.reg_write(UC_ARM64_REG_X0, 0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_plt_sigemptyset(uc, address, size, user_data):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        print(f"  [PLT] sigemptyset(0x{x0:x})")
        uc.mem_write(x0, b'\x00' * 64)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_plt_fork(uc, address, size, user_data):
        print(f"  [PLT] fork() -> 0")
        uc.reg_write(UC_ARM64_REG_X0, 0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_plt_nop(uc, address, size, user_data):
        print(f"  [PLT] {PLT_HOOKS.get(address, 'unknown')}(...) -> 0")
        uc.reg_write(UC_ARM64_REG_X0, 0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    # Install PLT hooks at vaddr (the BL targets are vaddrs, not absolute)
    for plt_addr, name in PLT_HOOKS.items():
        if name == "getpid":
            uc.hook_add(UC_HOOK_CODE, hook_plt_getpid, begin=plt_addr, end=plt_addr)
        elif name == "puts":
            uc.hook_add(UC_HOOK_CODE, hook_plt_puts, begin=plt_addr, end=plt_addr)
        elif name == "sigemptyset":
            uc.hook_add(UC_HOOK_CODE, hook_plt_sigemptyset, begin=plt_addr, end=plt_addr)
        elif name == "fork":
            uc.hook_add(UC_HOOK_CODE, hook_plt_fork, begin=plt_addr, end=plt_addr)
        else:
            uc.hook_add(UC_HOOK_CODE, hook_plt_nop, begin=plt_addr, end=plt_addr)

    print(f"[*] Installed {len(PLT_HOOKS)} PLT hooks at vaddr")

    # Hook BLR x8 at 0xedbd8 — callback through function pointer at [x22]
    # x22 is heap memory (0x70e6c592b8) not captured → function pointer is NULL
    def hook_blr_callback(uc, address, size, user_data):
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        if x8 == 0:
            # Mock callback: return 0 (success)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, LOAD_BASE + 0xedbdc)  # skip to next insn
            print(f"  [BLR] Mocked callback at 0x{address:x}: x8=0, returning 0")
        else:
            # Let the blr execute — but we need to handle the return
            # Set x30 to the next instruction so the callback can return
            lr = address + 4  # LOAD_BASE + 0xedbdc
            uc.reg_write(UC_ARM64_REG_X30, lr)
            uc.reg_write(UC_ARM64_REG_PC, x8)  # jump to the function
            print(f"  [BLR] Calling callback at 0x{x8:x}")

    # Hook BLR x8 at 0x5594c — dispatch loop callback
    def hook_blr_dispatch(uc, address, size, user_data):
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        if x8 == 0:
            # Mock: skip to next instruction (0x55950, the VM entry)
            uc.reg_write(UC_ARM64_REG_PC, LOAD_BASE + 0x55950)
            print(f"  [BLR] Mocked dispatch callback at 0x{address:x}: x8=0, continuing")
        else:
            lr = address + 4
            uc.reg_write(UC_ARM64_REG_X30, lr)
            uc.reg_write(UC_ARM64_REG_PC, x8)
            print(f"  [BLR] Calling dispatch callback at 0x{x8:x}")

    # Install BLR hooks at vaddr
    uc.hook_add(UC_HOOK_CODE, hook_blr_callback, begin=0xedbd8, end=0xedbd8)
    uc.hook_add(UC_HOOK_CODE, hook_blr_dispatch, begin=0x5594c, end=0x5594c)
    print(f"[*] Installed BLR hooks at 0xedbd8 and 0x5594c")

    # Hook memory access for unmapped regions — map on demand
    def hook_mem_unmapped(uc, access, address, size, value, user_data):
        # Map the page containing this address on demand
        page = address & ~0xfff
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            if access in (16, 19):  # READ or READ_UNMAPPED
                pass  # Just map, read will be re-tried
            elif access in (17, 20):  # WRITE or WRITE_UNMAPPED
                pass  # Just map, write will be re-tried
            print(f"  [MEM] Mapped on demand: 0x{page:x} (access={access} addr=0x{address:x})")
            return True  # Continue execution
        except Exception as e:
            print(f"  [MEM UNMAPPED] access={access} addr=0x{address:x} size={size} — can't map: {e}")
            return False

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)

    print(f"[*] Unicorn ready. .so at 0x{LOAD_BASE:x}, stack at 0x{STACK_BASE:x}")
    print(f"    bytecode at 0x{bc_addr:x} ({len(bytecode)} bytes)")
    print(f"    x23=0x{x23_val:x} -> *x23=0x{bc_addr:x}")
    print(f"    x24=0x{x24_val:x} (regfile)")

    return uc, insn_count, bc_addr


def run_vm(uc, insn_count):
    """Run the VM from entry point."""
    entry = LOAD_BASE + VM_ENTRY
    # Stop at the handler ret (0xedc10) or function epilogue (0x5d480)
    STOP_ADDRS = [
        LOAD_BASE + 0xedc10,  # handler ret (opcode 44 returns here)
        LOAD_BASE + 0x5d480,  # main function epilogue
    ]

    print(f"\n[*] Starting VM emulation at 0x{entry:x}...")
    print(f"    Stop at 0x{STOP_ADDRS[0]:x} or 0x{STOP_ADDRS[1]:x}")

    # Hook the ret instructions to stop
    stopped = [False]

    def hook_ret_stop(uc, address, size, user_data):
        print(f"  [STOP] Hit ret at 0x{address:x} — stopping emulation")
        uc.emu_stop()
        stopped[0] = True

    for addr in STOP_ADDRS:
        uc.hook_add(UC_HOOK_CODE, hook_ret_stop, begin=addr, end=addr)

    # Also hook the error path at 0xee04c which calls puts
    def hook_error_path(uc, address, size, user_data):
        print(f"  [ERROR_PATH] Hit 0x{address:x} — error/debug path, stopping")
        uc.emu_stop()
        stopped[0] = True

    uc.hook_add(UC_HOOK_CODE, hook_error_path, begin=0xee04c, end=0xee04c)

    try:
        uc.emu_start(entry, 0x6f5fe5d480, timeout=30_000_000, count=100_000)
    except Exception as e:
        print(f"  [!] Emulation stopped: {e}")

    print(f"\n[*] Emulation complete. {insn_count[0]} instructions executed. stopped={stopped[0]}")

    # Read the register file to extract slot16
    x24 = CAPTURED_STATE["x24"]
    regfile = uc.mem_read(x24, 32 * 8)
    print(f"\n=== Final Register File ===")
    for i in range(32):
        val = struct.unpack_from("<Q", regfile, i * 8)[0]
        print(f"  R[{i:2d}] = 0x{val:016x}")

    # Also read the stack area where slot16 might be written
    sp = CAPTURED_STATE["sp"]
    stack_data = uc.mem_read(sp - 0x100, 0x200)
    print(f"\n=== Stack around SP (0x{sp:x}) ===")
    for i in range(0, 0x200, 16):
        chunk = stack_data[i:i+16]
        if chunk != b'\x00' * 16:
            print(f"  0x{sp-0x100+i:x}: {chunk.hex()}")

    return uc


def main():
    so = load_so()
    print(f"[*] Loaded {SO} ({len(so)} bytes)")
    print(f"[*] LOAD_BASE = 0x{LOAD_BASE:x}")

    uc, insn_count, bc_addr = setup_unicorn(so)
    uc = run_vm(uc, insn_count)


if __name__ == "__main__":
    main()