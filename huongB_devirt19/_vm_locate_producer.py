#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_locate_producer.py — unicorn harness driven PURELY from the FULL live dump (_code_dump_full.bin,
# already decrypted + relocated). No capture needed for self-contained fns. Runs a native entry, stubs
# libc imports (via ELF .rela.plt), maps-on-fault, and hooks 16-byte memory writes to locate the slot16
# producer (its str-write into the header struct). Run under Python311 (has unicorn+elftools).
#   "/c/Program Files/Python311/python.exe" _vm_locate_producer.py <entry_off_hex> [maxinsn]
import json, struct, sys
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile

META = json.load(open("_code_dump_full_meta.json"))
BASE = int(META["base"], 16)
IMG  = open("_code_dump_full.bin", "rb").read()
IMGSZ = len(IMG)
ELF  = "bin/libmetasec_ov.so"

ENTRY = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x10ac2c
MAXINSN = int(sys.argv[2]) if len(sys.argv) > 2 else 2_000_000

def pa(x): return x & ~0xfff
def pae(x): return (x + 0xfff) & ~0xfff
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mapped = set()
def ensure(va, size=1):
    for a in range(pa(va), pae(va + size), 0x1000):
        if a not in mapped:
            uc.mem_map(a, 0x1000, UC_PROT_ALL); mapped.add(a)
def wr(va, b):
    ensure(va, len(b)); uc.mem_write(va, b)

# 1. map the full live dump verbatim (decrypted + relocated); pointers are already live-correct
for a in range(pa(BASE), pae(BASE + IMGSZ), 0x1000):
    uc.mem_map(a, 0x1000, UC_PROT_ALL); mapped.add(a)
uc.mem_write(BASE, IMG)
print(f"[+] mapped full dump @ {hex(BASE)} size {hex(IMGSZ)}")

# 2. import GOT stubbing from ELF .rela.plt (offsets match the same build)
STUB_BASE = 0x2_0000_0000; HEAP_BASE = 0x3_0000_0000
uc.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL); mapped.add(STUB_BASE)
for a in range(HEAP_BASE, HEAP_BASE + 0x800000, 0x1000): uc.mem_map(a, 0x1000, UC_PROT_ALL); mapped.add(a)
heap = {"p": HEAP_BASE + 0x1000}
def alloc(n):
    p = heap["p"]; heap["p"] = (p + (n or 16) + 15) & ~15; return p
elf = ELFFile(open(ELF, "rb"))
dynsym = elf.get_section_by_name(".dynsym")
imports = []
for sec in elf.iter_sections():
    if sec.header["sh_type"] == "SHT_RELA" and "plt" in sec.name:
        for r in sec.iter_relocations():
            name = dynsym.get_symbol(r["r_info_sym"]).name
            idx = len(imports); imports.append(name)
            sent = STUB_BASE + idx * 4
            wr(BASE + r["r_offset"], struct.pack("<Q", sent))
            uc.mem_write(sent, struct.pack("<I", 0xd65f03c0))
print(f"[+] stubbed {len(imports)} imports")
FIXTIME = 1787560000
def do_import(uc, name):
    x = [uc.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
    ret = 0
    try:
        if name.endswith("memcpy") or name.endswith("memmove") or name in ("memcpy","memmove"):
            d,s,n=x[0],x[1],x[2]
            if n and n<0x100000: ensure(d,n); uc.mem_write(d, bytes(uc.mem_read(s,n)))
            ret=d
        elif name=="memset":
            d,c,n=x[0],x[1],x[2]
            if n and n<0x100000: ensure(d,n); uc.mem_write(d, bytes([c&0xff])*n)
            ret=d
        elif name in ("malloc","valloc","aligned_alloc","_Znwm","_Znam"):
            ret=alloc(x[0] if x[0] and x[0]<0x400000 else 0x1000)
        elif name=="calloc":
            n=(x[0]*x[1]) or 0x100; ret=alloc(n if n<0x400000 else 0x1000); uc.mem_write(ret, b"\x00"*min(n,0x1000))
        elif name in ("free","_ZdlPv","_ZdaPv","_ZdlPvm","_ZdaPvm"): ret=0
        elif name=="strlen":
            s=x[0]; n=0
            while n<0x10000 and uc.mem_read(s+n,1)[0]!=0: n+=1
            ret=n
        elif name in ("__stack_chk_fail","abort","__assert2","longjmp"): ret=0
        else: ret=0
    except Exception: ret=0
    uc.reg_write(UC_ARM64_REG_X0, ret & (2**64-1))
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
def on_stub(uc, addr, size, data):
    if STUB_BASE <= addr < STUB_BASE + len(imports)*4:
        do_import(uc, imports[(addr - STUB_BASE)//4])
uc.hook_add(UC_HOOK_CODE, on_stub, begin=STUB_BASE, end=STUB_BASE+0x10000)

# 3. TLS for stack cookie (mrs tpidr_el0; ldr [x+0x28])
TLS = 0x4_0000_0000
uc.mem_map(TLS, 0x1000, UC_PROT_ALL); mapped.add(TLS)
uc.mem_write(TLS+0x28, struct.pack("<Q", 0xC0FFEE1234567890))
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)

# 4. stack
STK = 0x7_0000_0000
for a in range(STK-0x80000, STK, 0x1000): uc.mem_map(a,0x1000,UC_PROT_ALL); mapped.add(a)
SP = STK - 0x8000
uc.reg_write(UC_ARM64_REG_SP, SP)
SENT = 0x1_2340_0000
uc.mem_map(SENT & ~0xfff, 0x1000, UC_PROT_ALL); mapped.add(SENT & ~0xfff)
uc.reg_write(UC_ARM64_REG_LR, SENT)

# 5. map-on-fault
faults = {}
def on_unmapped(uc, access, addr, size, value, data):
    pg = pa(addr)
    if pg not in mapped:
        try: uc.mem_map(pg, 0x1000, UC_PROT_ALL); mapped.add(pg)
        except: return False
    faults[pg] = faults.get(pg,0)+1
    return True
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

# 6. mem-write hook: log 8/16-byte writes into heap structs (candidate slot16 producer)
writes = []   # (pc_off, addr, size, value)
def on_write(uc, access, addr, size, value, data):
    if HEAP_BASE <= addr < HEAP_BASE+0x800000 or (BASE+0x1c0000) <= addr:  # heap or data region
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if len(writes) < 200000: writes.append((pc-BASE, addr, size, value))
    return True
uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

# 7. run
ninsn = {"n":0}
def on_code(uc, addr, size, data):
    ninsn["n"] += 1
uc.hook_add(UC_HOOK_CODE, on_code, begin=BASE, end=BASE+IMGSZ)

print(f"[+] running entry 0x{ENTRY:x} (max {MAXINSN} insn)...")
reached = False
try:
    uc.emu_start(BASE+ENTRY, SENT, count=MAXINSN)
    reached = True
    print(f"[+] RET reached SENTINEL after {ninsn['n']} insn")
except UcError as e:
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print(f"[!] stopped: {e} @ pc=0x{pc-BASE:x} (off) after {ninsn['n']} insn")

if reached or ninsn["n"]:
    w0 = uc.reg_read(UC_ARM64_REG_X0)
    print(f"[=] x0(ret)=0x{w0:x}  writes-logged={len(writes)}  fault-pages={len(faults)}")
    # 16-byte writes = stp (size 16 not native to unicorn hook; look for adjacent 8+8 same-pc)
    from collections import Counter
    pcw = Counter(w[0] for w in writes)
    print("[=] top write-PCs (off -> count):")
    for pc,c in pcw.most_common(12):
        print(f"      0x{pc:06x}  x{c}")
