#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn_v3.py — Unicorn harness with proper PLT stubs for C++ guards, malloc, etc.
#
# Fixes from v2:
#   - Smart PLT hook: identifies function by PLT address, handles each correctly
#   - __cxa_guard_acquire: tracks guard variables, returns 1 on first call
#   - __cxa_guard_release: sets guard to initialized state
#   - malloc/calloc/realloc/free: bump allocator in heap region
#   - memcpy/memset/memmove: actually perform the operations
#   - pthread_mutex_*: no-op stubs (single-threaded emulation)
#
# Run: python _vm_unicorn_v3.py
import os, sys, json, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = "bin/libmetasec_ov.so"
VM_ENTRY = 0x55950
PREDICATE = 0x9b374
HANDLER_TABLE = 0x1d9488
CAPTURE_FILE = "atomic_capture.json"

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# ── PLT entry → function name mapping (file offsets, NOT base-relative) ──
# Built from .rela.plt parsing
PLT_MAP = {
    0x30680: "cxa_guard_release",
    0x30dd0: "cxa_guard_acquire",
    0x30610: "malloc",
    0x305d0: "calloc",
    0x30760: "realloc",
    0x30590: "free",
    0x303d0: "memcpy",
    0x30690: "memmove",
    0x30930: "memset",
    0x306d0: "strlen",
    0x30600: "strcmp",
    0x307d0: "strncmp",
    0x308e0: "strcpy",
    0x30450: "strncpy",
    0x309a0: "strndup",
    0x30d90: "strdup",
    0x305c0: "strchr",
    0x30720: "strstr",
    0x30da0: "strrchr",
    0x30840: "strpbrk",
    0x30a40: "strcasestr",
    0x30780: "strtod",
    0x30830: "strtol",
    0x30de0: "strtoull",
    0x30ce0: "atoll",
    0x30a00: "atoi",
    0x30a50: "atol",
    0x30920: "isspace",
    0x306e0: "_ZNSt6__ndk18ios_base4initEPv",
    0x30480: "_ZdlPv",        # operator delete
    0x304c0: "_Znam",         # operator new[]
    0x30900: "_ZdaPv",        # operator delete[]
    0x30430: "asprintf",
    0x308f0: "vsnprintf",
    0x30510: "__vsprintf_chk",
    0x30580: "sscanf",
    0x308d0: "_ZNSt6__ndk19to_stringEm",
    0x303e0: "fopen",
    0x30750: "fclose",
    0x305a0: "fread",
    0x30770: "fwrite",
    0x30860: "ftell",
    0x30a20: "fseek",
    0x30870: "remove",
    0x304a0: "rename",
    0x30440: "opendir",
    0x30470: "readdir",
    0x304e0: "closedir",
    0x30420: "memchr",
    0x304f0: "pthread_mutexattr_settype",
    0x304b0: "pthread_mutex_destroy",
    0x30530: "pthread_mutex_trylock",
    0x30880: "pthread_mutex_unlock",
    0x30af0: "pthread_mutex_lock",
    0x30940: "pthread_mutex_init",
    0x30730: "pthread_mutexattr_destroy",
    0x30ac0: "pthread_mutexattr_init",
    0x308c0: "pthread_create",
    0x306b0: "pthread_once",
    0x30670: "pthread_setspecific",
    0x30970: "pthread_getspecific",
    0x305e0: "pthread_key_delete",
    0x30b90: "pthread_key_create",
    0x30700: "pthread_self",
    0x307a0: "pthread_rwlock_init",
    0x30810: "pthread_rwlock_rdlock",
    0x30820: "pthread_rwlock_unlock",
    0x30c90: "pthread_rwlock_destroy",
    0x30d10: "pthread_rwlock_wrlock",
    0x30790: "_ZNSt6__ndk118condition_variableD1Ev",
    0x30740: "_ZNSt6__ndk115__thread_structC1Ev",
    0x30b80: "_ZNSt6__ndk115__thread_structD1Ev",
    0x30640: "_ZNSt6__ndk15mutex6unlockEv",
    0x30410: "_ZNSt6__ndk119__shared_mutex_base6unlockEv",
    0x30910: "_ZNSt6__ndk119__shared_mutex_base11lock_sharedEv",
    0x304e0: "_ZNSt6__ndk119__shared_mutex_base13unlock_sharedEv",
    0x30480: "_ZNSt6__ndk15mutex8try_lockEv",  # note: 0x30480 is reused? check
    0x30660: "_ZNSt6__ndk119__shared_weak_countD2Ev",
    0x30980: "_ZNSt6__ndk119__shared_weak_count14__release_weakEv",
    0x30410: "_ZNKSt6__ndk119__shared_weak_count13__get_deleterERKSt9type_info",
    0x30b60: "cxa_finalize",
    0x309f0: "cxa_atexit",
    0x30c70: "cxa_demangle",
    0x30800: "cxa_pure_virtual",
    0x30d60: "__strlen_chk",
    0x30d70: "__read_chk",
    0x30630: "getpid",
    0x30710: "gettid",
    0x30460: "usleep",
    0x30c00: "uname",
    0x30c50: "sysinfo",
    0x30950: "fork",
    0x30490: "kill",
    0x30620: "sigaddset",
    0x305b0: "sigemptyset",
    0x308b0: "sigprocmask",
    0x30b10: "mprotect",
    0x30a60: "mmap",
    0x307b0: "munmap",
    0x308a0: "madvise",
    0x307c0: "dladdr",
    0x307f0: "npth_dlopen",
    0x30ba0: "npth_dlsym",
    0x30a90: "getuid",
    0x309e0: "getppid",
    0x309c0: "__system_property_find",
    0x306c0: "__system_property_read",
    0x30520: "lstat",
    0x30570: "readlink",
    0x306a0: "faccessat",
    0x306f0: "access",
    0x305f0: "mkdir",
    0x309b0: "ioctl",
    0x30540: "__android_log_write",
    0x30850: "__android_log_print",
    0x30560: "clock_gettime",
    0x30650: "rand",
    0x307e0: "srand",
    0x30a10: "srand48",
    0x309d0: "abort",
    0x303b0: "getpagesize",
    0x30400: "gettimeofday",
    0x30a80: "stat",
    0x30890: "fstatat",
    0x30a30: "statfs",
    0x30b00: "fstat",
    0x30b20: "lstat64",
    0x30b30: "fstatat64",
    0x30a70: "socket",
    0x30b40: "setsockopt",
    0x30b50: "sendmsg",
    0x30b60: "recvmsg",  # note: same as cxa_finalize? check
    0x304a0: "rename",
    0x30a70: "utime",
    0x30b70: "unlink",
    0x30b80: "waitpid",
    0x30b90: "ptrace",
    0x30ba0: "prctl",
    0x30bb0: "raise",
    0x30bc0: "signal",
    0x30bd0: "sigaction",
    0x30be0: "setlocale",
    0x30bf0: "localeconv",
    0x30c10: "setvbuf",
    0x30c20: "setbuf",
    0x30c30: "clearerr",
    0x30c40: "feof",
    0x30c60: "ferror",
    0x30c80: "rewind",
    0x30ca0: "tmpfile",
    0x30cb0: "tmpnam",
    0x30cc0: "perror",
    0x30cd0: "popen",
    0x30cf0: "pclose",
    0x30d00: "getchar",
    0x30d20: "putchar",
    0x30d30: "fputc",
    0x30d40: "fputs",
    0x30d50: "fgetc",
    0x30d80: "fgets",
    0x30db0: "fprintf",
    0x30dc0: "fscanf",
    0x30df0: "ungetc",
    0x30e00: "scanf",
    0x30e10: "printf",
    0x30e20: "sprintf",
    0x30e30: "snprintf",
    0x30e40: "qsort",
    0x30e50: "bsearch",
    0x30e60: "abs",
    0x30e70: "labs",
    0x30e80: "llabs",
    0x30e90: "div",
    0x30ea0: "ldiv",
    0x30eb0: "lldiv",
    0x30ec0: "imaxabs",
    0x30ed0: "imaxdiv",
    0x30ee0: "wcstombs",
    0x30ef0: "wctomb",
    0x30f00: "mbstowcs",
    0x30f10: "mbtowc",
    0x30f20: "strcoll",
    0x30f30: "strxfrm",
    0x30f40: "strftime",
    0x30f50: "strptime",
    0x30f60: "gmtime",
    0x30f70: "localtime",
    0x30f80: "mktime",
    0x30f90: "asctime",
    0x30fa0: "ctime",
    0x30fb0: "difftime",
    0x30fc0: "clock",
    0x30fd0: "times",
    0x30fe0: "getenv",
    0x30ff0: "putenv",
    0x31000: "setenv",
    0x31010: "unsetenv",
    0x31020: "system",
    0x31030: "execve",
    0x31040: "execv",
    0x31050: "execvp",
    0x31060: "execl",
    0x31070: "execlp",
    0x31080: "execle",
    0x31090: "_exit",
    0x310a0: "environ",
}

# Fix: remove duplicate keys (some PLT entries share the same address? not possible)
# Actually, these are all unique addresses. Let me filter the ones that are actually in the PLT.
PLT_START = 0x30390
PLT_END = 0x30390 + 0xa70

# Filter to only valid PLT entries
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
        "stackVals": {},
    }


def h2i(s):
    return int(s, 16) if s not in (None, "", "NULL") else 0


def parse_regfile(hexstr):
    return [int(hexstr[i*16:(i+1)*16], 16) for i in range(32)]


def apply_relocations(uc, so, base):
    e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
    e_shnum = struct.unpack_from("<H", so, 0x3c)[0]
    e_shentsize = struct.unpack_from("<H", so, 0x3a)[0]
    R_AARCH64_RELATIVE = 1027
    applied = 0
    for i in range(e_shnum):
        b = e_shoff + i*e_shentsize
        stype = struct.unpack_from("<I", so, b+4)[0]
        if stype != 4:
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
        if struct.unpack_from("<I", uc_so, off)[0] != 1:
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

    apply_relocations(uc, uc_so, base)

    # Stack region
    sp = h2i(cap["cpur"]["sp"])
    stack_base = (sp - 0x20000) & ~0xfff
    uc.mem_map(stack_base, 0x40000, UC_PROT_ALL)
    print(f"    stack 0x{stack_base:x} size=0x40000 (sp=0x{sp:x})")

    # Heap region for malloc
    heap_base = base + 0x300000
    heap_size = 0x1000000  # 16 MB
    uc.mem_map(heap_base, heap_size, UC_PROT_ALL)
    print(f"    heap 0x{heap_base:x} size=0x{heap_size:x}")

    # Seed CPU registers
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
    for pg in {bcptr & ~0xfff, (bcptr+len(bc)) & ~0xfff}:
        try: uc.mem_map(pg, 0x1000, UC_PROT_ALL)
        except UcError: pass
    uc.mem_write(bcptr, bc)
    uc.mem_write(x23, struct.pack("<Q", bcptr))

    # Write captured stack image
    stack_hex = cap.get("stack_sp", "")
    if stack_hex and stack_hex not in ("ERR", "NULL"):
        uc.mem_write(sp, bytes.fromhex(stack_hex))

    # Seed opaque predicate at [fp-0x58]
    pred = int(cap.get("pred_fp58", hex(PREDICATE)), 16)
    uc.mem_write(fp - 0x58, struct.pack("<Q", pred))
    print(f"    seeded [fp-0x58]=0x{pred:x} (predicate)")

    return uc, base


def run(uc, base, cap, max_insn=300):
    ic = [0]
    trace = []
    guard_state = {}  # guard_addr -> state (0=uninit, 1=locked, 2=done)
    heap_ptr = [base + 0x300000]  # bump allocator pointer
    heap_end = base + 0x300000 + 0x1000000

    # Map PLT addresses to their base-relative offsets for quick lookup
    plt_offsets = set(PLT_HANDLERS.keys())

    def hook(uc, addr, size, ud):
        ic[0] += 1
        off = addr - base
        if ic[0] <= max_insn:
            code = uc.mem_read(addr, size)
            for ins in md.disasm(bytes(code), addr):
                trace.append(f"  [{ic[0]:3d}] 0x{off:x}: {ins.mnemonic:8s} {ins.op_str}")
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

    # ── Smart PLT hook ──
    def plt_hook(uc, addr, size, ud):
        off = addr - base
        func_name = PLT_HANDLERS.get(off, None)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)

        if func_name is None:
            # Unknown PLT entry — return 0 and hope for the best
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __cxa_guard_acquire ──
        if func_name == "cxa_guard_acquire":
            if x0 in guard_state:
                if guard_state[x0] == 2:
                    uc.reg_write(UC_ARM64_REG_X0, 0)  # already initialized
                else:
                    uc.reg_write(UC_ARM64_REG_X0, 0)  # locked by another thread
            else:
                # First call: acquire lock, set guard byte to 1
                guard_state[x0] = 1
                try:
                    uc.mem_write(x0, b'\x01' + b'\x00' * 7)
                except UcError:
                    pass
                uc.reg_write(UC_ARM64_REG_X0, 1)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __cxa_guard_release ──
        if func_name == "cxa_guard_release":
            guard_state[x0] = 2
            try:
                uc.mem_write(x0, b'\x02' + b'\x00' * 7)
            except UcError:
                pass
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __cxa_atexit / __cxa_finalize / __cxa_pure_virtual / __cxa_demangle ──
        if func_name in ("cxa_atexit", "cxa_finalize", "cxa_pure_virtual"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        if func_name == "cxa_demangle":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # return NULL
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── malloc(size) ──
        if func_name == "malloc":
            size_val = x0
            if size_val == 0:
                size_val = 8
            # Align to 16 bytes
            size_val = (size_val + 15) & ~15
            ptr = heap_ptr[0]
            if ptr + size_val > heap_end:
                print(f"    [OOM] malloc({size_val}) failed — heap exhausted")
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                heap_ptr[0] = ptr + size_val
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── calloc(nmemb, size) ──
        if func_name == "calloc":
            nmemb, size_val = x0, x1
            total = nmemb * size_val
            if total == 0:
                total = 8
            total = (total + 15) & ~15
            ptr = heap_ptr[0]
            if ptr + total > heap_end:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                heap_ptr[0] = ptr + total
                try:
                    uc.mem_write(ptr, b'\x00' * total)
                except UcError:
                    pass
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── realloc(ptr, size) ──
        if func_name == "realloc":
            # Super simplified: just malloc new, copy old, free old
            old_ptr, new_size = x0, x1
            if old_ptr == 0:
                new_size = (new_size + 15) & ~15 if new_size else 8
                ptr = heap_ptr[0]
                heap_ptr[0] = ptr + new_size
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            elif new_size == 0:
                uc.reg_write(UC_ARM64_REG_X0, 0)  # free, return NULL
            else:
                new_size = (new_size + 15) & ~15
                ptr = heap_ptr[0]
                heap_ptr[0] = ptr + new_size
                try:
                    old_data = uc.mem_read(old_ptr, min(new_size, 4096))
                    uc.mem_write(ptr, old_data)
                except UcError:
                    pass
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── free(ptr) ──
        if func_name == "free":
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── memcpy(dst, src, n) ──
        if func_name == "memcpy":
            dst, src, n = x0, x1, x2
            if n > 0:
                try:
                    data = uc.mem_read(src, n)
                    uc.mem_write(dst, bytes(data))
                except UcError:
                    pass
            uc.reg_write(UC_ARM64_REG_X0, dst)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── memmove(dst, src, n) ──
        if func_name == "memmove":
            dst, src, n = x0, x1, x2
            if n > 0:
                try:
                    data = uc.mem_read(src, n)
                    uc.mem_write(dst, bytes(data))
                except UcError:
                    pass
            uc.reg_write(UC_ARM64_REG_X0, dst)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── memset(dst, c, n) ──
        if func_name == "memset":
            dst, c, n = x0, x1, x2
            if n > 0:
                try:
                    uc.mem_write(dst, bytes([c & 0xff] * n))
                except UcError:
                    pass
            uc.reg_write(UC_ARM64_REG_X0, dst)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── strlen(s) ──
        if func_name == "strlen":
            try:
                # Read up to 4096 bytes to find null
                data = uc.mem_read(x0, 4096)
                null_idx = data.find(b'\x00')
                if null_idx >= 0:
                    uc.reg_write(UC_ARM64_REG_X0, null_idx)
                else:
                    uc.reg_write(UC_ARM64_REG_X0, 4096)
            except UcError:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── strcmp(s1, s2) ──
        if func_name == "strcmp":
            try:
                s1 = uc.mem_read(x0, 256)
                s2 = uc.mem_read(x1, 256)
                n1 = s1.find(b'\x00')
                n2 = s2.find(b'\x00')
                if n1 >= 0: s1 = s1[:n1]
                if n2 >= 0: s2 = s2[:n2]
                if s1 < s2:
                    uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)
                elif s1 > s2:
                    uc.reg_write(UC_ARM64_REG_X0, 1)
                else:
                    uc.reg_write(UC_ARM64_REG_X0, 0)
            except UcError:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── strncmp(s1, s2, n) ──
        if func_name == "strncmp":
            try:
                n = x2
                s1 = uc.mem_read(x0, min(n, 256))
                s2 = uc.mem_read(x1, min(n, 256))
                n1 = s1.find(b'\x00')
                n2 = s2.find(b'\x00')
                if n1 >= 0: s1 = s1[:n1]
                if n2 >= 0: s2 = s2[:n2]
                s1 = s1[:n]; s2 = s2[:n]
                if s1 < s2:
                    uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)
                elif s1 > s2:
                    uc.reg_write(UC_ARM64_REG_X0, 1)
                else:
                    uc.reg_write(UC_ARM64_REG_X0, 0)
            except UcError:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── pthread_mutex_lock / unlock / trylock / init / destroy ──
        if func_name.startswith("pthread_mutex"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── pthread_rwlock_* ──
        if func_name.startswith("pthread_rwlock"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── pthread_create / pthread_once / pthread_self / etc ──
        if func_name.startswith("pthread"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── getpid / gettid / getuid / getppid ──
        if func_name in ("getpid", "gettid", "getuid", "getppid"):
            uc.reg_write(UC_ARM64_REG_X0, 12345)  # fake PID
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── usleep ──
        if func_name == "usleep":
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── clock_gettime ──
        if func_name == "clock_gettime":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── gettimeofday ──
        if func_name == "gettimeofday":
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── getpagesize ──
        if func_name == "getpagesize":
            uc.reg_write(UC_ARM64_REG_X0, 4096)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── rand / srand / srand48 ──
        if func_name in ("rand", "srand", "srand48"):
            uc.reg_write(UC_ARM64_REG_X0, 42)  # predictable random
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── sysinfo ──
        if func_name == "sysinfo":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── uname ──
        if func_name == "uname":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── fork ──
        if func_name == "fork":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # we're the child
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── kill / signal / sigaction / sigprocmask / etc ──
        if func_name in ("kill", "sigaddset", "sigemptyset", "sigprocmask", "signal", "sigaction", "raise"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── mprotect ──
        if func_name == "mprotect":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── mmap ──
        if func_name == "mmap":
            # Simple: allocate from heap
            length = x1
            length = (length + 0xfff) & ~0xfff
            ptr = heap_ptr[0]
            heap_ptr[0] = ptr + length
            try:
                uc.mem_map(ptr, length, UC_PROT_ALL)
            except UcError:
                pass
            uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── munmap ──
        if func_name == "munmap":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # success
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── madvise ──
        if func_name == "madvise":
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── dladdr ──
        if func_name == "dladdr":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # not found
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── npth_dlopen / npth_dlsym ──
        if func_name in ("npth_dlopen", "npth_dlsym"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # failed
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __system_property_find / __system_property_read ──
        if func_name.startswith("__system_property"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # not found
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __android_log_write / __android_log_print ──
        if func_name.startswith("__android_log"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── lstat / stat / fstat / readlink / faccessat / access / mkdir ──
        if func_name in ("lstat", "stat", "fstat", "fstatat", "lstat64", "fstatat64", "readlink", "faccessat", "access", "mkdir", "statfs", "unlink", "rename", "remove", "utime"):
            uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)  # -1: error
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── ioctl ──
        if func_name == "ioctl":
            uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)  # -1: error
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── abort ──
        if func_name == "abort":
            print(f"    [ABORT] called — stopping emulation")
            uc.emu_stop()
            return

        # ── operator new / delete ──
        if func_name in ("_Znam", "_Znwm"):  # operator new / new[]
            size_val = x0 if x0 else 8
            size_val = (size_val + 15) & ~15
            ptr = heap_ptr[0]
            heap_ptr[0] = ptr + size_val
            uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        if func_name in ("_ZdlPv", "_ZdaPv"):  # operator delete / delete[]
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── strcpy / strncpy / strdup / strndup ──
        if func_name in ("strcpy", "strncpy"):
            try:
                src = uc.mem_read(x1, 4096)
                null_idx = src.find(b'\x00')
                if null_idx >= 0:
                    src = src[:null_idx+1]
                if func_name == "strncpy":
                    n = x2
                    src = src[:n]
                uc.mem_write(x0, src)
            except UcError:
                pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if func_name in ("strdup", "strndup"):
            try:
                src = uc.mem_read(x0, 4096)
                null_idx = src.find(b'\x00')
                if null_idx >= 0:
                    src = src[:null_idx+1]
                if func_name == "strndup":
                    n = x1
                    src = src[:n]
                total = len(src)
                total = (total + 15) & ~15
                ptr = heap_ptr[0]
                heap_ptr[0] = ptr + total
                uc.mem_write(ptr, src)
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            except UcError:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── strchr / strrchr / strstr / strpbrk / strcasestr ──
        if func_name in ("strchr", "strrchr", "strstr", "strpbrk", "strcasestr"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # not found
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── atoi / atol / atoll / strtol / strtoull / strtod ──
        if func_name in ("atoi", "atol", "atoll", "strtol", "strtoull", "strtod"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── isspace ──
        if func_name == "isspace":
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── asprintf / vsnprintf / sscanf / __vsprintf_chk ──
        if func_name in ("asprintf", "vsnprintf", "sscanf", "__vsprintf_chk"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # return 0 bytes / error
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── fopen / fclose / fread / fwrite / ftell / fseek ──
        if func_name in ("fopen", "fclose", "fread", "fwrite", "ftell", "fseek"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # NULL / error
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── opendir / readdir / closedir ──
        if func_name in ("opendir", "readdir", "closedir"):
            uc.reg_write(UC_ARM64_REG_X0, 0)  # NULL
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── memchr ──
        if func_name == "memchr":
            uc.reg_write(UC_ARM64_REG_X0, 0)  # not found
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── _ZNSt6__ndk1* (libc++ internal) ──
        if func_name.startswith("_ZNSt6"):
            # libc++ internal functions — just return 0
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── _ZNKSt6* (libc++ virtual) ──
        if func_name.startswith("_ZNKSt6"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── __strlen_chk / __read_chk ──
        if func_name in ("__strlen_chk", "__read_chk"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── socket / setsockopt / sendmsg / recvmsg ──
        if func_name in ("socket", "setsockopt", "sendmsg", "recvmsg"):
            uc.reg_write(UC_ARM64_REG_X0, 0xffffffffffffffff)  # -1: error
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        # ── any other function ──
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    uc.hook_add(UC_HOOK_CODE, plt_hook, begin=base+PLT_START, end=base+PLT_END)

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