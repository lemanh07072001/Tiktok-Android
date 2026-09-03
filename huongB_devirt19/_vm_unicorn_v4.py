#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn_v4.py — Run slot16 bytecode from start (0x17bc6c).
#
# Uses atomic_capture VM state (registers, control block) but:
#   - Points bytecode to slot16 start (0x17bc6c)
#   - Zeroes regfile (clean start)
#   - Traces VM execution, dumps regfile + output
#
# Run: python _vm_unicorn_v4.py
import os, sys, json, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = "bin/libmetasec_ov.so"
VM_ENTRY = 0x55950
PREDICATE = 0x9b374
CAPTURE_FILE = "atomic_capture.json"

# Slot16 bytecode range
SLOT16_BC_START = 0x17bc6c   # file offset of first opcode
SLOT16_BC_SIZE = 102728       # total bytecode size

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# ── PLT handler map (same as v3) ──
PLT_START = 0x30390
PLT_END = 0x30390 + 0xa70

PLT_MAP = {
    0x30680: "cxa_guard_release", 0x30dd0: "cxa_guard_acquire",
    0x30610: "malloc", 0x305d0: "calloc", 0x30760: "realloc", 0x30590: "free",
    0x303d0: "memcpy", 0x30690: "memmove", 0x30930: "memset",
    0x306d0: "strlen", 0x30600: "strcmp", 0x307d0: "strncmp",
    0x308e0: "strcpy", 0x30450: "strncpy", 0x309a0: "strndup", 0x30d90: "strdup",
    0x305c0: "strchr", 0x30720: "strstr", 0x30da0: "strrchr", 0x30840: "strpbrk",
    0x30780: "strtod", 0x30830: "strtol", 0x30de0: "strtoull",
    0x30ce0: "atoll", 0x30a00: "atoi", 0x303b0: "getpagesize",
    0x30630: "getpid", 0x30710: "gettid", 0x30460: "usleep",
    0x30c00: "uname", 0x30c50: "sysinfo", 0x30950: "fork",
    0x30490: "kill", 0x30620: "sigaddset", 0x305b0: "sigemptyset", 0x308b0: "sigprocmask",
    0x30b10: "mprotect", 0x307b0: "munmap", 0x308a0: "madvise",
    0x307c0: "dladdr", 0x307f0: "npth_dlopen", 0x30ba0: "npth_dlsym",
    0x309c0: "__system_property_find", 0x306c0: "__system_property_read",
    0x30540: "__android_log_write", 0x30850: "__android_log_print",
    0x30560: "clock_gettime", 0x30400: "gettimeofday",
    0x30650: "rand", 0x307e0: "srand",
    0x309d0: "abort", 0x30b60: "cxa_finalize", 0x309f0: "cxa_atexit",
    0x30c70: "cxa_demangle", 0x30800: "cxa_pure_virtual",
    0x30d60: "__strlen_chk", 0x30480: "_ZdlPv", 0x304c0: "_Znam", 0x30900: "_ZdaPv",
    0x30430: "asprintf", 0x308f0: "vsnprintf", 0x30510: "__vsprintf_chk",
    0x30580: "sscanf", 0x30420: "memchr", 0x30920: "isspace",
    0x303e0: "fopen", 0x30750: "fclose", 0x305a0: "fread", 0x30860: "ftell", 0x30a20: "fseek",
    0x30870: "remove", 0x304a0: "rename", 0x30440: "opendir", 0x304e0: "closedir",
    0x30520: "lstat", 0x30a80: "stat", 0x30b00: "fstat", 0x30890: "fstatat",
    0x30570: "readlink", 0x306a0: "faccessat", 0x306f0: "access", 0x305f0: "mkdir",
    0x309b0: "ioctl", 0x309e0: "getppid", 0x30a90: "getuid",
    0x30a60: "mmap", 0x30a30: "statfs", 0x30a70: "utime",
    0x308d0: "_ZNSt6__ndk19to_stringEm",
    0x306e0: "_ZNSt6__ndk18ios_base4initEPv",
    0x30480: "_ZdlPv", 0x304c0: "_Znam", 0x30900: "_ZdaPv",
}
# Note: 0x30480 appears twice in the original map, but it's _ZdlPv (operator delete)

PLT_HANDLERS = {k: v for k, v in PLT_MAP.items() if PLT_START <= k < PLT_END}


def load_capture(idx=0):
    data = json.load(open(CAPTURE_FILE, encoding="utf-8"))
    a = data[idx]
    return {
        "base": a["base"],
        "cpur": a["regs"],
        "regfile": a["regfile"],
        "bytecode256": a["bytecode"],
        "bcPtr": a["bcptr"],
        "pred_fp58": a["pred_fp58"],
        "stack_sp": a.get("stack_sp", ""),
    }


def h2i(s):
    return int(s, 16) if s not in (None, "", "NULL") else 0


def apply_relocations(uc, so, base):
    e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
    e_shnum = struct.unpack_from("<H", so, 0x3c)[0]
    e_shentsize = struct.unpack_from("<H", so, 0x3a)[0]
    R_AARCH64_RELATIVE = 1027
    applied = 0
    for i in range(e_shnum):
        b = e_shoff + i*e_shentsize
        stype = struct.unpack_from("<I", so, b+4)[0]
        if stype != 4: continue
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
                except UcError: pass
    print(f"    applied {applied} RELATIVE relocations")


def setup(uc_so, cap):
    base = h2i(cap["base"])
    print(f"[*] LOAD_BASE = 0x{base:x}, predicate = 0x{PREDICATE:x}")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map ELF PT_LOAD segments
    e_phoff = struct.unpack_from("<Q", uc_so, 0x20)[0]
    e_phnum = struct.unpack_from("<H", uc_so, 0x38)[0]
    e_phentsize = struct.unpack_from("<H", uc_so, 0x36)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsize
        if struct.unpack_from("<I", uc_so, off)[0] != 1: continue
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

    apply_relocations(uc, uc_so, base)

    # Stack
    sp = h2i(cap["cpur"]["sp"])
    stack_base = (sp - 0x20000) & ~0xfff
    uc.mem_map(stack_base, 0x40000, UC_PROT_ALL)
    print(f"    stack 0x{stack_base:x} size=0x40000 (sp=0x{sp:x})")

    # Heap
    heap_base = base + 0x300000
    heap_size = 0x1000000
    uc.mem_map(heap_base, heap_size, UC_PROT_ALL)
    print(f"    heap 0x{heap_base:x} size=0x{heap_size:x}")

    # Seed CPU registers from capture
    for i in range(29):
        v = h2i(cap["cpur"].get(f"x{i}", "0"))
        uc.reg_write(globals()[f"UC_ARM64_REG_X{i}"], v)
    fp = h2i(cap["cpur"]["fp"])
    uc.reg_write(UC_ARM64_REG_FP, fp)
    uc.reg_write(UC_ARM64_REG_LR, h2i(cap["cpur"]["lr"]))
    uc.reg_write(UC_ARM64_REG_SP, sp)

    # ── SLOT16: point bytecode to start ──
    x23 = h2i(cap["cpur"]["x23"])  # address of bytecode ptr
    bcptr_slot16 = base + SLOT16_BC_START
    # Ensure the bytecode pages are mapped (they should be from the first segment)
    uc.mem_write(x23, struct.pack("<Q", bcptr_slot16))
    print(f"    [SLOT16] *x23 = 0x{bcptr_slot16:x} (bytecode start)")

    # ── SLOT16: use original regfile (NOT zeroed — header handler needs it) ──
    x24 = h2i(cap["cpur"]["x24"])
    # Keep the original regfile from the capture
    # rf = b'\x00' * (32 * 8)  # NO — header handler reads regfile[25] for next PC
    # uc.mem_write(x24, rf)
    # print(f"    [SLOT16] regfile zeroed at 0x{x24:x}")
    print(f"    [SLOT16] regfile at 0x{x24:x} (keeping original values)")

    # Write captured stack image
    stack_hex = cap.get("stack_sp", "")
    if stack_hex and stack_hex not in ("ERR", "NULL"):
        uc.mem_write(sp, bytes.fromhex(stack_hex))

    # Seed predicate
    pred = int(cap.get("pred_fp58", hex(PREDICATE)), 16)
    uc.mem_write(fp - 0x58, struct.pack("<Q", pred))
    print(f"    seeded [fp-0x58]=0x{pred:x}")

    return uc, base


def run(uc, base, cap, max_insn=200000):
    ic = [0]
    dispatch_count = [0]
    guard_state = {}
    heap_ptr = [base + 0x300000]
    heap_end = base + 0x300000 + 0x1000000

    def hook(uc, addr, size, ud):
        ic[0] += 1
        off = addr - base
        # Trace first 50 instructions
        if ic[0] <= 50:
            code = uc.mem_read(addr, size)
            for ins in md.disasm(bytes(code), addr):
                print(f"    [{ic[0]:4d}] 0x{off:06x}: {ins.mnemonic:8s} {ins.op_str}")
        # Catch any br x15 (dispatch) — encoding: 0xd61f01e0
        code = uc.mem_read(addr, size)
        is_br_x15 = (struct.unpack_from("<I", code, 0)[0] == 0xd61f01e0)
        if is_br_x15:
            dispatch_count[0] += 1
            x15 = uc.reg_read(UC_ARM64_REG_X15)
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            try:
                bc_ptr = struct.unpack_from("<Q", uc.mem_read(x23, 8))[0]
                opword = struct.unpack_from("<I", uc.mem_read(bc_ptr, 4))[0]
                op_idx = opword & 0x3f
                operand = struct.unpack_from("<I", uc.mem_read(bc_ptr + 4, 4))[0]
                handler_off = (x15-base) & 0xffffffffffffffff
                bc_off = bc_ptr - base
                if dispatch_count[0] <= 50 or dispatch_count[0] % 50 == 0:
                    print(f"    [DISPATCH #{dispatch_count[0]}] op={op_idx:2d} bc_off=0x{bc_off:x} "
                          f"opword=0x{opword:08x} operand=0x{operand:08x} handler=0x{handler_off:x}")
            except Exception as e:
                print(f"    [DISPATCH #{dispatch_count[0]}] err={e}")
        if ic[0] > max_insn:
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

    # ── PLT hook (same as v3) ──
    def plt_hook(uc, addr, size, ud):
        off = addr - base
        func_name = PLT_HANDLERS.get(off, None)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)

        if func_name is None:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "cxa_guard_acquire":
            if x0 in guard_state:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                guard_state[x0] = 1
                try: uc.mem_write(x0, b'\x01' + b'\x00' * 7)
                except UcError: pass
                uc.reg_write(UC_ARM64_REG_X0, 1)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "cxa_guard_release":
            guard_state[x0] = 2
            try: uc.mem_write(x0, b'\x02' + b'\x00' * 7)
            except UcError: pass
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("cxa_atexit", "cxa_finalize", "cxa_pure_virtual", "cxa_demangle"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "malloc":
            size_val = x0 if x0 else 8
            size_val = (size_val + 15) & ~15
            ptr = heap_ptr[0]
            if ptr + size_val > heap_end:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                heap_ptr[0] = ptr + size_val
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "calloc":
            total = (x0 * x1) if (x0 and x1) else 8
            total = (total + 15) & ~15
            ptr = heap_ptr[0]
            if ptr + total > heap_end:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                heap_ptr[0] = ptr + total
                try: uc.mem_write(ptr, b'\x00' * total)
                except UcError: pass
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "realloc":
            if x0 == 0:
                new_size = (x1 + 15) & ~15 if x1 else 8
                ptr = heap_ptr[0]; heap_ptr[0] = ptr + new_size
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            elif x1 == 0:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                new_size = (x1 + 15) & ~15
                ptr = heap_ptr[0]; heap_ptr[0] = ptr + new_size
                try:
                    old = uc.mem_read(x0, min(new_size, 4096))
                    uc.mem_write(ptr, bytes(old))
                except UcError: pass
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "free":
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "memcpy":
            if x2 > 0:
                try:
                    data = uc.mem_read(x1, x2)
                    uc.mem_write(x0, bytes(data))
                except UcError: pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "memmove":
            if x2 > 0:
                try:
                    data = uc.mem_read(x1, x2)
                    uc.mem_write(x0, bytes(data))
                except UcError: pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "memset":
            if x2 > 0:
                try: uc.mem_write(x0, bytes([x1 & 0xff] * x2))
                except UcError: pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "strlen":
            try:
                data = uc.mem_read(x0, 4096)
                null_idx = data.find(b'\x00')
                uc.reg_write(UC_ARM64_REG_X0, null_idx if null_idx >= 0 else 4096)
            except UcError: uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("strcmp", "strncmp"):
            try:
                n = x2 if func_name == "strncmp" else 256
                s1 = uc.mem_read(x0, min(n, 256))
                s2 = uc.mem_read(x1, min(n, 256))
                n1 = s1.find(b'\x00'); n2 = s2.find(b'\x00')
                if n1 >= 0: s1 = s1[:n1]
                if n2 >= 0: s2 = s2[:n2]
                if s1 < s2: uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)
                elif s1 > s2: uc.reg_write(UC_ARM64_REG_X0, 1)
                else: uc.reg_write(UC_ARM64_REG_X0, 0)
            except UcError: uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "abort":
            print(f"    [ABORT] called — stopping"); uc.emu_stop(); return

        if func_name in ("_Znam", "_Znwm"):
            size_val = x0 if x0 else 8
            size_val = (size_val + 15) & ~15
            ptr = heap_ptr[0]; heap_ptr[0] = ptr + size_val
            uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("_ZdlPv", "_ZdaPv"):
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("strcpy", "strncpy"):
            try:
                src = uc.mem_read(x1, 4096)
                idx = src.find(b'\x00')
                if idx >= 0: src = src[:idx+1]
                if func_name == "strncpy": src = src[:x2]
                uc.mem_write(x0, src)
            except UcError: pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("strdup", "strndup"):
            try:
                src = uc.mem_read(x0, 4096)
                idx = src.find(b'\x00')
                if idx >= 0: src = src[:idx+1]
                if func_name == "strndup": src = src[:x1]
                total = (len(src) + 15) & ~15
                ptr = heap_ptr[0]; heap_ptr[0] = ptr + total
                uc.mem_write(ptr, src)
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            except UcError: uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("getpid", "gettid", "getuid", "getppid"):
            uc.reg_write(UC_ARM64_REG_X0, 12345)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name == "getpagesize":
            uc.reg_write(UC_ARM64_REG_X0, 4096)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("rand", "srand", "srand48"):
            uc.reg_write(UC_ARM64_REG_X0, 42)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("lstat", "stat", "fstat", "fstatat", "lstat64", "fstatat64",
                         "readlink", "faccessat", "access", "mkdir", "statfs", "unlink",
                         "rename", "remove", "utime", "ioctl"):
            uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("mmap", "mprotect", "munmap", "madvise", "sysinfo", "uname",
                         "clock_gettime", "gettimeofday", "usleep", "fork", "kill",
                         "sigaddset", "sigemptyset", "sigprocmask", "signal", "sigaction",
                         "raise", "dladdr", "npth_dlopen", "npth_dlsym",
                         "__system_property_find", "__system_property_read",
                         "__android_log_write", "__android_log_print",
                         "__strlen_chk", "__read_chk", "asprintf", "vsnprintf",
                         "__vsprintf_chk", "sscanf", "memchr", "isspace",
                         "fopen", "fclose", "fread", "fwrite", "ftell", "fseek",
                         "opendir", "readdir", "closedir", "strchr", "strrchr",
                         "strstr", "strpbrk", "strcasestr", "atoi", "atol", "atoll",
                         "strtol", "strtoull", "strtod", "socket", "setsockopt",
                         "sendmsg", "recvmsg", "_ZNSt6__ndk19to_stringEm",
                         "_ZNSt6__ndk18ios_base4initEPv"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # Generic fallback for pthread_*, _ZNSt6*, _ZNKSt6*
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    uc.hook_add(UC_HOOK_CODE, plt_hook, begin=base+PLT_START, end=base+PLT_END)

    entry = base + VM_ENTRY
    print(f"\n[*] emulate from 0x{entry:x} (off 0x{VM_ENTRY:x})")
    try:
        uc.emu_start(entry, 0, count=5000)
    except UcError as e:
        print(f"    [emu stopped] {e} at insn #{ic[0]}")

    print(f"\n[*] {ic[0]} instructions, {dispatch_count[0]} dispatches")

    # Dump regfile
    x24 = h2i(cap["cpur"]["x24"])
    print("\n=== regfile after ===")
    for i in range(32):
        v = struct.unpack_from("<Q", uc.mem_read(x24+i*8, 8))[0]
        if v: print(f"  R[{i:2d}] = 0x{v:016x}")

    # Dump output buffer if present
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    if x1:
        try:
            out = uc.mem_read(x1, 64)
            print(f"\n=== output at x1=0x{x1:x} ===")
            print(f"  hex: {out.hex()}")
        except UcError:
            pass


def main():
    so = open(SO, "rb").read()
    print(f"[*] loaded {SO} ({len(so)} bytes)")
    cap = load_capture(0)
    uc, base = setup(so, cap)
    run(uc, base, cap)


if __name__ == "__main__":
    main()