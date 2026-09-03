#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_vm_replay_capture.py — unicorn replay of the VM slot16 computation from a LIVE single-shot capture
(_singleshot.json: registers + regfile + reachable memory windows at 0x55950 entry).

Agent C: the 0x55950 function is self-contained on the slot16 path (0 BL/syscall/JNI). So given the
entry registers + the memory it dereferences (captured), unicorn should run it to `ret` and produce
slot16 in the VM output — validated against the slot16 values captured on the same thread.
"""
import json, struct, sys
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile

SO = "bin/libmetasec_ov.so"
CAP = json.load(open("_singleshot.json"))
ENT = CAP["entry"]
BASE = int(ENT["base"], 16)
CTXPTR = int(ENT["ctxptr"], 16) if ENT.get("ctxptr") else None
SLOTS = [s["slot16"] for s in CAP["slots"] if s["slot16"] != "00" * 16
         and s["slot16"] != "5f75675f73686f707461625f6e65773d"]  # drop the ascii false-positive
# broaden: include all historically captured slot16 (entry may match any)
import glob as _g
for _fn in ("_corr_data.json", "slot16_newphone_verified.json", "_light2_obs.json", "_bufcorr.json"):
    try:
        _d = json.load(open(_fn)); _it = _d if isinstance(_d, list) else _d.get("obs", [])
        for _o in _it:
            if isinstance(_o, dict) and _o.get("slot16") and _o["slot16"] != "00"*16:
                SLOTS.append(_o["slot16"])
    except Exception: pass
SLOTS = list(dict.fromkeys(s.lower() for s in SLOTS))

REGMAP = {
    'x0':UC_ARM64_REG_X0,'x1':UC_ARM64_REG_X1,'x2':UC_ARM64_REG_X2,'x3':UC_ARM64_REG_X3,
    'x4':UC_ARM64_REG_X4,'x5':UC_ARM64_REG_X5,'x6':UC_ARM64_REG_X6,'x7':UC_ARM64_REG_X7,
    'x8':UC_ARM64_REG_X8,'x9':UC_ARM64_REG_X9,'x10':UC_ARM64_REG_X10,'x11':UC_ARM64_REG_X11,
    'x12':UC_ARM64_REG_X12,'x13':UC_ARM64_REG_X13,'x14':UC_ARM64_REG_X14,'x15':UC_ARM64_REG_X15,
    'x16':UC_ARM64_REG_X16,'x17':UC_ARM64_REG_X17,'x18':UC_ARM64_REG_X18,'x19':UC_ARM64_REG_X19,
    'x20':UC_ARM64_REG_X20,'x21':UC_ARM64_REG_X21,'x22':UC_ARM64_REG_X22,'x23':UC_ARM64_REG_X23,
    'x24':UC_ARM64_REG_X24,'x25':UC_ARM64_REG_X25,'x26':UC_ARM64_REG_X26,'x27':UC_ARM64_REG_X27,
    'x28':UC_ARM64_REG_X28,'fp':UC_ARM64_REG_X29,'lr':UC_ARM64_REG_X30,'sp':UC_ARM64_REG_SP,
}

def pa(x): return x & ~0xfff
def pae(x): return (x + 0xfff) & ~0xfff

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mapped = []
def ensure(va, size):
    s = pa(va); e = pae(va + size)
    for a in range(s, e, 0x1000):
        if not any(m <= a < m + 0x1000 for m in mapped):
            uc.mem_map(a, 0x1000, UC_PROT_ALL); mapped.append(a)
def wr(va, b):
    ensure(va, len(b)); uc.mem_write(va, b)

# 1. map .so image + apply R_AARCH64_RELATIVE
elf = ELFFile(open(SO, "rb"))
for s in elf.iter_segments():
    if s["p_type"] == "PT_LOAD":
        wr(BASE + s["p_vaddr"], s.data())
nrel = 0
for sec in elf.iter_sections():
    if sec.header["sh_type"] in ("SHT_RELA", "SHT_REL"):
        for r in sec.iter_relocations():
            if r["r_info_type"] == 1027:  # R_AARCH64_RELATIVE
                wr(BASE + r["r_offset"], struct.pack("<Q", BASE + r["r_addend"]))
                nrel += 1
print(f"[+] mapped .so @ {hex(BASE)}, applied {nrel} RELATIVE relocs")

# 2. captured memory windows + stack + regfile + live bytecode
for va_hex, h in ENT["mem"].items():
    wr(int(va_hex, 16), bytes.fromhex(h))
wr(int(ENT["stackBase"], 16), bytes.fromhex(ENT["stack"]))
PC_OFF = int(ENT["regs"]["pc"], 16) - BASE
if PC_OFF != 0x52924 and ENT.get("regfile"):   # at true entry 0x52924 the prologue builds the regfile
    wr(int(ENT["regs"]["x24"], 16), bytes.fromhex(ENT["regfile"]))
if ENT.get("bytecode") and ENT.get("bcptr"):
    wr(int(ENT["bcptr"], 16), bytes.fromhex(ENT["bytecode"]))
if ENT.get("soRW") and ENT.get("soRWbase"):   # runtime-initialized .so globals (handler tables)
    wr(int(ENT["soRWbase"], 16), bytes.fromhex(ENT["soRW"]))
if ENT.get("bcFull") and ENT.get("bcFullBase"):  # full live (partially-decrypted) bytecode
    wr(int(ENT["bcFullBase"], 16), bytes.fromhex(ENT["bcFull"]))
print(f"[+] wrote {len(ENT['mem'])} mem windows + stack + regfile + bytecode + soRW + bcFull")

# CRITICAL: captured mem was read WHILE frida hooks were active -> .so code pages contain frida
# Interceptor patches (ldr x16,#lit; br x16 -> gum trampoline). Re-write clean executable segments
# from the .so FILE to remove the patches, then re-apply the live (self-modified) bytecode on top.
npatch = 0
for s in elf.iter_segments():
    if s["p_type"] == "PT_LOAD" and (s["p_flags"] & 0x1):  # executable segment
        wr(BASE + s["p_vaddr"], s.data()); npatch += 1
if ENT.get("bcFull") and ENT.get("bcFullBase"):
    wr(int(ENT["bcFullBase"], 16), bytes.fromhex(ENT["bcFull"]))
if ENT.get("soData") and ENT.get("soDataBase"):   # runtime-initialized .data.rel.ro tables (0x1d9488/0x1d9688, ptr slots) — MUST win over static file+relocs
    wr(int(ENT["soDataBase"], 16), bytes.fromhex(ENT["soData"]))
print(f"[+] un-patched frida hooks: re-wrote {npatch} clean executable segment(s) + re-applied bcFull + soData")

# 3. set registers
for name, rid in REGMAP.items():
    if name in ENT["regs"]:
        uc.reg_write(rid, int(ENT["regs"][name], 16))

# 3a. FRIDA GUM CLEANUP: the capture ran with frida hooks active, so the stack + some registers hold
# frida gum-trampoline pointers (rwxp anon regions). The VM's real values there are .so return-addresses.
# Replace gum-trampoline pointers with the slot16-invocation's clean caller (base+0x9ff1c).
import re as _re
CLEAN_RET = BASE + 0x9ff1c
gum_ranges = []
try:
    for l in open("_maps.txt", encoding="utf-8", errors="ignore"):
        m = _re.match(r'([0-9a-f]+)-([0-9a-f]+) (rwx|r-x)p \S+ \S+ \S+\s*(.*)', l)
        if m and (not m.group(4).strip() or m.group(4).startswith('[anon')):
            gum_ranges.append((int(m.group(1),16), int(m.group(2),16)))
except Exception: pass
def is_gum(v): return any(a <= v < b for a,b in gum_ranges)
ncleaned = 0
# clean registers
for name, rid in REGMAP.items():
    try:
        v = uc.reg_read(rid)
        if is_gum(v): uc.reg_write(rid, CLEAN_RET); ncleaned += 1
    except Exception: pass
# clean the captured stack region (scan for gum pointers, replace)
try:
    sbase = int(ENT["stackBase"], 16); slen = len(bytes.fromhex(ENT["stack"]))
    data = bytearray(uc.mem_read(sbase, slen))
    for o in range(0, slen-8, 8):
        v = struct.unpack_from("<Q", data, o)[0]
        if is_gum(v): struct.pack_into("<Q", data, o, CLEAN_RET); ncleaned += 1
    uc.mem_write(sbase, bytes(data))
except Exception as ex: print("[!] stack clean err", ex)
print(f"[+] frida gum cleanup: replaced {ncleaned} gum-trampoline pointers with clean ret {hex(CLEAN_RET)}")

# 3b. GOT/PLT libc stub layer — fill import GOT slots with sentinels, hook to implement libc
STUB_BASE = 0x2_0000_0000
HEAP_BASE = 0x3_0000_0000
uc.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL)
uc.mem_map(HEAP_BASE, 0x400000, UC_PROT_ALL)
heap = {"p": HEAP_BASE + 0x1000}
def alloc(n):
    p = heap["p"]; heap["p"] = (p + n + 15) & ~15; return p
imports = []  # idx -> name
dynsym = elf.get_section_by_name(".dynsym")
for sec in elf.iter_sections():
    if sec.header["sh_type"] == "SHT_RELA" and "plt" in sec.name:
        for r in sec.iter_relocations():
            name = dynsym.get_symbol(r["r_info_sym"]).name
            idx = len(imports); imports.append(name)
            sent = STUB_BASE + idx * 4
            wr(BASE + r["r_offset"], struct.pack("<Q", sent))
            uc.mem_write(sent, struct.pack("<I", 0xd65f03c0))  # ret (placeholder; hooked below)
print(f"[+] filled {len(imports)} import GOT slots with stubs")
FIXTIME = 1787560000
import collections as _c
IMPCNT = _c.Counter()
def do_import(uc, name):
    IMPCNT[name] += 1
    x = [uc.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
    ret = 0
    try:
        if name in ("memcpy","memmove") or name.endswith("memcpy") or name.endswith("memmove"):
            d,s,n = x[0],x[1],x[2]
            if n and n < 0x100000: uc.mem_write(d, bytes(uc.mem_read(s,n)))
            ret = d
        elif name == "memset":
            d,c,n = x[0],x[1],x[2]
            if n and n < 0x100000: uc.mem_write(d, bytes([c&0xff])*n)
            ret = d
        elif name in ("malloc","calloc","_Znwm","_Znam","valloc","aligned_alloc"):
            n = x[1] if name=="calloc" else x[0]
            if name=="calloc": n = x[0]*x[1]
            ret = alloc(n if n and n<0x400000 else 0x1000)
            if name=="calloc": uc.mem_write(ret, b"\x00"*(n if n<0x400000 else 0x1000))
        elif name in ("free","_ZdlPv","_ZdaPv","_ZdlPvm","_ZdaPvm"):
            ret = 0
        elif name == "strlen":
            s=x[0]; n=0
            while n<0x10000 and uc.mem_read(s+n,1)[0]!=0: n+=1
            ret=n
        elif name == "memchr":
            s,c,n=x[0],x[1]&0xff,x[2]; ret=0
            b=bytes(uc.mem_read(s,n)) if n and n<0x100000 else b""
            i=b.find(bytes([c])); ret=(s+i) if i>=0 else 0
        elif name in ("strncpy","strcpy","strlcpy"):
            d,s=x[0],x[1]; n=x[2] if name!="strcpy" else 0x1000
            b=bytes(uc.mem_read(s, min(n,0x1000)))
            z=b.find(b"\x00"); b=b[:z if z>=0 else len(b)]
            uc.mem_write(d, b + b"\x00"); ret=d
        elif name == "gettimeofday":
            if x[0]: uc.mem_write(x[0], struct.pack("<qq", FIXTIME, 0)); ret=0
        elif name in ("time",):
            if x[0]: uc.mem_write(x[0], struct.pack("<q", FIXTIME))
            ret=FIXTIME
        elif name == "getpagesize":
            ret=0x1000
        elif name in ("pthread_mutex_lock","pthread_mutex_unlock","pthread_mutex_destroy",
                      "pthread_mutex_init","pthread_once","pthread_cond_signal","pthread_cond_broadcast",
                      "usleep","sched_yield"):
            ret=0
        else:
            ret=0  # default: return 0 (best-effort)
    except Exception:
        ret=0
    uc.reg_write(UC_ARM64_REG_X0, ret & 0xffffffffffffffff)
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

def on_stub(uc, addr, size, data):
    if STUB_BASE <= addr < STUB_BASE + len(imports)*4:
        idx = (addr - STUB_BASE)//4
        do_import(uc, imports[idx])
uc.hook_add(UC_HOOK_CODE, on_stub, begin=STUB_BASE, end=STUB_BASE + 0x10000)

# 4. on-demand map for anything not captured (zero page) + trace
missing = {}
def on_unmapped(uc, access, addr, size, value, data):
    pg = pa(addr)
    if not any(m <= pg < m + 0x1000 for m in mapped):
        try: uc.mem_map(pg, 0x1000, UC_PROT_ALL); mapped.append(pg)
        except: pass
    missing[pg] = missing.get(pg, 0) + 1
    return True
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

import os as _os
VMTRACE = _os.environ.get("VMTRACE")
vmtrace = []            # full per-instruction trace for the lifter: (pc_off, decrypted_word, op, regfile_hex)
dispatch = {"n": 0}
trace = []
vmpcs = set()
vmpc_seq = []          # ordered VM-PC (bytecode offset) sequence, rolling last N
regfile_at = {}        # vmpc_off -> list of regfile-qword snapshots (to find stuck/counter values)
X24 = int(ENT["regs"]["x24"], 16)
def on_block(uc, addr, size, data):
    dispatch["n"] += 1
    if len(trace) < 100000: trace.append(addr)
    off = addr - BASE
    # VM fetch happens at these decode blocks (they do ldr from [x23])
    if off in (0x5ad2c, 0x5c0fc, 0x55890):
        try:
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            bc = struct.unpack("<Q", uc.mem_read(x23, 8))[0]
            vmpcs.add(bc)
            bco = bc - BASE if BASE <= bc < BASE+0x200000 else bc
            vmpc_seq.append(bco)
            if len(vmpc_seq) > 4000: vmpc_seq.pop(0)
            if VMTRACE and len(vmtrace) < 120000:
                word = struct.unpack("<I", uc.mem_read(bc, 4))[0]
                x24r = uc.reg_read(UC_ARM64_REG_X24)
                rf = uc.mem_read(x24r, 256).hex()
                spr = uc.reg_read(UC_ARM64_REG_SP)
                stk = uc.mem_read(spr, 256).hex()   # scratch window (op42 writes [sp+0x70])
                vmtrace.append((hex(bco), hex(word), word & 0x3f, rf, stk))
            # snapshot regfile at loop-start to find the loop counter/condition
            if bco == 0x17ca74 and len(regfile_at) < 8:
                x24 = uc.reg_read(UC_ARM64_REG_X24)
                rf = struct.unpack("<32Q", uc.mem_read(x24, 256))
                regfile_at[len(regfile_at)] = rf
        except: pass
uc.hook_add(UC_HOOK_BLOCK, on_block)

# track memory reads during the loop (once looping steadily) to find the spin-wait condition value
import collections as _cc
in_loop = {"v": False}
memreads = _cc.Counter(); memread_vals = {}
def on_memread(uc, access, addr, size, value, data):
    if dispatch["n"] > 500000:   # loop is fully established -> all reads are loop reads
        memreads[addr] += 1
        try: memread_vals[addr] = int.from_bytes(uc.mem_read(addr, size), "little")
        except: pass
uc.hook_add(UC_HOOK_MEM_READ, on_memread)
memwrites = _cc.Counter(); memwrite_seq = {}
def on_memwrite(uc, access, addr, size, value, data):
    if dispatch["n"] > 500000:
        memwrites[addr] += 1
        memwrite_seq.setdefault(addr, [])
        if len(memwrite_seq[addr]) < 6: memwrite_seq[addr].append(value & ((1<<(size*8))-1))
uc.hook_add(UC_HOOK_MEM_WRITE, on_memwrite)

# HƯỚNG-A: target slot16 write-hook — replay continues past interp into producer (0x9b74c); watch for the
# expected slot16 halves being stored -> that store PC = the PRODUCER of slot16. Cheap (value compare only).
_TGT = _os.environ.get("TARGET_SLOT16")
_tgtb = bytes.fromhex(_TGT) if _TGT else None
_tgt_lo = struct.unpack("<Q", _tgtb[:8])[0] if _tgtb else None
_tgt_hi = struct.unpack("<Q", _tgtb[8:16])[0] if _tgtb else None
producer_hits = []
he_writes = []   # high-entropy heap writes after the interp: (pc_off, addr, value)
def _hi_entropy(v):
    b = v.to_bytes(8,'little'); ds = len(set(b))
    if ds < 6: return False
    asc = sum(1 for x in b if 0x20<=x<=0x7e)
    return asc < 6   # not ASCII
def on_target_write(uc, access, addr, size, value, data):
    value &= 0xffffffffffffffff
    if dispatch["n"] > 120 and size in (8,16) and 0x7000000000 <= addr < 0x8000000000:
        if _tgtb and (value == _tgt_lo or value == _tgt_hi):
            pc = uc.reg_read(UC_ARM64_REG_PC)
            producer_hits.append((pc-BASE, addr))
            print("  *** SLOT16-HALF WRITE @ PC 0x%x addr 0x%x ***" % (pc-BASE, addr), flush=True)
        elif _hi_entropy(value):
            pc = uc.reg_read(UC_ARM64_REG_PC)
            if len(he_writes) < 4000: he_writes.append((pc-BASE, addr, value))
    return True
uc.hook_add(UC_HOOK_MEM_WRITE, on_target_write)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def on_code(uc, addr, size, data):
    trace.append(("i", addr))
# (instruction-level trace optional; block trace is enough)

# sanity: [x23] should = bcptr; [fp-0x58] should = bias 0x9b374
x23 = int(ENT["regs"]["x23"], 16); fp = int(ENT["regs"]["fp"], 16)
try:
    v_x23 = struct.unpack("<Q", uc.mem_read(x23, 8))[0]
    print(f"[chk] [x23]={hex(v_x23)}  bcptr={ENT.get('bcptr')}  match={hex(v_x23)==ENT.get('bcptr')}")
except Exception as e: print("[chk] [x23] read err", e)
try:
    v_bias = struct.unpack("<Q", uc.mem_read(fp - 0x58, 8))[0]
    print(f"[chk] [fp-0x58]={hex(v_bias)} (expect bias 0x9b374)")
except Exception as e: print("[chk] [fp-0x58] read err", e)

# 5. run from pc to epilogue ret (0x5d480) / cap
pc = int(ENT["regs"]["pc"], 16)
END = BASE + 0x5d484
print(f"[+] running from pc={hex(pc)} until ret {hex(END)} ...")
err = None
reached_ret = {"v": False}
X4_CAP = int(ENT["regs"]["x4"], 16) if "x4" in ENT["regs"] else None
epi = {"done": False}
def on_ret_check(uc, addr, size, data):
    # F's real epilogue is ~0x5d464; but it's hit for nested returns too. Only the FINAL one (after the full
    # crypto, ~88k blocks) is F's real return. Dump the outbuf THERE before the (wrong) caller overwrites it.
    if addr in (END, BASE+0x5d480, BASE+0x5d464) and dispatch["n"] > int(_os.environ.get("EPI_MIN","40000")) and not epi["done"]:
        epi["done"] = True; reached_ret["v"] = True
        try:
            print("\n=== F EPILOGUE %s: outbuf @captured-x4=%s ===" % (hex(addr-BASE), hex(X4_CAP)))
            for lbl, a in (("x4", X4_CAP), ("[x4+8]->", None), ("[x4+0x10]->", None)):
                pass
            raw = bytes(uc.mem_read(X4_CAP, 64)); print("  x4[0:64]=", raw.hex())
            for off in (0x8, 0x10, 0x0):
                try:
                    p = struct.unpack("<Q", raw[off:off+8])[0]
                    if 0x1000 < p < 0x8000000000:
                        d = bytes(uc.mem_read(p, 32)); print("  [x4+%#x]=%#x -> %s" % (off, p, d.hex()))
                except Exception: pass
            # search a window around x4 + its derefs for any pool slot16
            import re as _r2
            allb = raw
            for off in (0x8,0x10,0x0,0x18):
                try:
                    p=struct.unpack("<Q",raw[off:off+8])[0]
                    if 0x1000<p<0x8000000000: allb += bytes(uc.mem_read(p,64))
                except Exception: pass
            hexall = allb.hex()
            for sv in SLOTS:
                if sv in hexall: print("  *** SLOT16 MATCH in outbuf:", sv)
        except Exception as ex: print("  [epi dump err]", ex)
        uc.emu_stop()
uc.hook_add(UC_HOOK_BLOCK, on_ret_check, begin=BASE+0x5d400, end=BASE+0x5d490)

# STUB external call-outs: F's VM calls into C++ runtime vtables in OTHER libraries (unmapped).
# On any fetch into unmapped memory, map a 'ret' page there so the call returns immediately (x0 unchanged).
# This lets the self-contained ARX crypto proceed past device-context/logging call-outs.
# A 'ret' stub page: any external/vtable call-out lands here and returns immediately.
STUB = 0x111100000
uc.mem_map(STUB, 0x1000, UC_PROT_ALL); mapped.append(STUB)
uc.mem_write(STUB, b'\xc0\x03\x5f\xd6' * 1024)   # 'ret'
STUBQ = struct.pack("<Q", STUB) * 512            # page full of pointers-to-STUB
stub_pages = {"n": 0, "fetch": 0, "lazy": 0}
# LAZY on-demand page fetch from the LIVE captured process (same base, no restart).
import subprocess as _sp
LAZYPID = _os.environ.get("LAZYPID")
_lazycache = {}
def lazy_fetch(page):
    if not LAZYPID: return None
    if page in _lazycache: return _lazycache[page]
    try:
        r = _sp.run(["adb","-s","ce05160592d7b31902","shell",
                     "su -c 'dd if=/proc/%s/mem bs=4096 skip=%d count=1 2>/dev/null | xxd -p -c 256'" % (LAZYPID, page//0x1000)],
                    capture_output=True, timeout=20)
        h = r.stdout.decode("ascii","ignore").replace("\n","").replace("\r","")
        b = bytes.fromhex(h) if h else b""
        b = (b + b"\x00"*0x1000)[:0x1000]
        _lazycache[page] = b if any(b) else None
        return _lazycache[page]
    except Exception:
        _lazycache[page] = None
        return None
def on_data_unmapped(uc, access, addr, size, value, data):
    page = addr & ~0xfff
    real = lazy_fetch(page)
    try:
        uc.mem_map(page, 0x1000, UC_PROT_ALL); mapped.append(page)
        if real is not None:
            uc.mem_write(page, real); stub_pages["lazy"] += 1
        else:
            uc.mem_write(page, STUBQ); stub_pages["n"] += 1
    except Exception:
        pass
    return True
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_data_unmapped)
uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_data_unmapped)
def on_fetch_unmapped(uc, access, addr, size, value, data):
    page = addr & ~0xfff
    real = lazy_fetch(page)
    try:
        uc.mem_map(page, 0x1000, UC_PROT_ALL); mapped.append(page)
        if real is not None:
            uc.mem_write(page, real); stub_pages["lazy"] += 1
        else:
            uc.mem_write(page, b'\xc0\x03\x5f\xd6' * 1024); stub_pages["fetch"] += 1
    except Exception:
        pass
    return True
uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, on_fetch_unmapped)

# PROACTIVE CONTEXT FETCH: the injected ctxptr's object graph is device-stable and lives ONLY in the live
# process (not in the frozen BFS capture, which seeded from a stale getter ptr). Fetch its page + pointer
# closure from the live process and OVERWRITE unicorn memory with the correct data, so F reads real context.
if CTXPTR is not None and LAZYPID:
    def is_ptr(v): return 0x1000_0000 < v < 0x80_0000_0000
    frontier = [CTXPTR & ~0xfff]; seen = set(); nfetch = 0; print("[.] proactive fetch start...", flush=True)
    for _lvl in range(5):
        nxt = []
        for pg in frontier:
            if pg in seen or len(seen) > 120: continue
            seen.add(pg)
            b = lazy_fetch(pg)
            if b is None: continue
            wr(pg, b); nfetch += 1
            for o in range(0, 0x1000-8, 8):
                v = struct.unpack_from("<Q", b, o)[0]
                if is_ptr(v) and (v & ~0xfff) not in seen: nxt.append(v & ~0xfff)
        frontier = nxt
    print(f"[+] proactive context fetch: overwrote {nfetch} live pages from ctxptr {hex(CTXPTR)} closure")

# ROBUST call-out skip: F's VM issues `blr Xn` into C++ vtables in OTHER libraries. Detect any blr
# whose target is OUTSIDE the libmetasec image (and not a PLT-import stub) and SKIP it (PC+=4, treat as
# a no-op returning). Keeps in-image dispatch (`br x15`) intact; only external native call-outs are stubbed.
_XREG = [globals()[f"UC_ARM64_REG_X{i}"] for i in range(31)]
IMG_LO, IMG_HI = BASE, BASE + 0x200000
skipped = {"n": 0, "tgts": {}}
def in_valid_code(t):
    return (IMG_LO <= t < IMG_HI) or (0x200000000 <= t < 0x200010000) or (STUB <= t < STUB+0x1000)
def on_code(uc, addr, size, data):
    try:
        word = int.from_bytes(uc.mem_read(addr, 4), "little")
    except Exception:
        return
    if (word & 0xFFFFFC1F) == 0xD63F0000:           # blr Xn
        rn = (word >> 5) & 0x1f
        tgt = 0 if rn == 31 else uc.reg_read(_XREG[rn])
        if not in_valid_code(tgt):
            skipped["n"] += 1
            off_here = addr - BASE
            skipped["tgts"][hex(off_here)] = skipped["tgts"].get(hex(off_here),0)+1
            # singleton-getter call-out at 0x13b010: method writes the CONTEXT ptr to [sp] (x1=sp).
            # Inject the captured device-stable context ptr so the getter returns it (not 0 -> derail).
            if off_here == 0x13b010 and CTXPTR is not None:
                try: uc.mem_write(uc.reg_read(UC_ARM64_REG_SP), struct.pack("<Q", CTXPTR)); skipped["ctx_inj"] = skipped.get("ctx_inj",0)+1
                except Exception: pass
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)      # other external call-outs -> void
            uc.reg_write(UC_ARM64_REG_PC, addr + 4)   # skip the call
    elif False and (word & 0xFFFFFC1F) == 0xD61F0000:  # br-skip DISABLED (was causing derail)
        rn = (word >> 5) & 0x1f
        tgt = 0 if rn == 31 else uc.reg_read(_XREG[rn])
        if not in_valid_code(tgt):
            skipped["n"] += 1
            skipped["tgts"]["br@"+hex(addr-BASE)] = skipped["tgts"].get("br@"+hex(addr-BASE),0)+1
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr if in_valid_code(lr) else addr + 4)
uc.hook_add(UC_HOOK_CODE, on_code, begin=IMG_LO, end=IMG_HI)
try:
    uc.emu_start(pc, 0, count=200_000_000, timeout=400*1000000)
except UcError as ex:
    err = ex
print(f"[+] reached_ret={reached_ret['v']}"); print(f"[+] distinct VM-PCs visited = {len(vmpcs)}")
if VMTRACE:
    import json as _json
    with open("_vm_trace.jsonl", "w") as _tf:
        for _t in vmtrace: _tf.write(_json.dumps({"pc":_t[0],"word":_t[1],"op":_t[2],"rf":_t[3],"stk":_t[4]})+"\n")
    print(f"[+] VMTRACE: wrote {len(vmtrace)} VM instructions -> _vm_trace.jsonl")
print(f"[+] STUB fired: data-unmapped={stub_pages['n']} fetch-unmapped={stub_pages['fetch']} blr-skipped={skipped['n']} ctx_inj={skipped.get('ctx_inj',0)} lazy={stub_pages['lazy']}")
if skipped["tgts"]: print(f"[+] blr-skip sites (off:count): {dict(list(skipped['tgts'].items())[:12])}")
# HƯỚNG-A producer localization: find PCs that wrote 2 ADJACENT high-entropy 8-byte values (=16B slot16 store)
if producer_hits:
    from collections import Counter as _C
    print(f"\n[HƯỚNG-A] *** TARGET SLOT16 written at PCs: {_C(p[0] for p in producer_hits).most_common(8)} ***")
if he_writes:
    byaddr = {a: (pc,v) for pc,a,v in he_writes}
    pairs = []
    for pc,a,v in he_writes:
        if a+8 in byaddr:
            pairs.append((pc, a, v, byaddr[a+8][1]))
    from collections import Counter as _C
    print(f"\n[HƯỚNG-A] high-entropy heap writes: {len(he_writes)}, adjacent-16B pairs: {len(pairs)}")
    print(f"[HƯỚNG-A] producer-candidate PCs (16B-store): {_C(p[0] for p in pairs).most_common(10)}")
    for pc,a,lo,hi in pairs[:6]:
        print("   PC 0x%06x -> addr 0x%x  slot16=%s%s" % (pc, a, lo.to_bytes(8,'little').hex(), hi.to_bytes(8,'little').hex()))
try:
    print(f"[+] can map page 0? ", end="")
    uc.mem_map(0, 0x1000); print("YES"); uc.mem_unmap(0,0x1000)
except Exception as _e: print("NO:", _e)
# find the loop cycle: smallest period P such that vmpc_seq[-P:] repeats
def find_period(seq):
    for P in range(1, len(seq)//3):
        if seq[-P:] == seq[-2*P:-P] == seq[-3*P:-2*P]:
            return P
    return None
P = find_period(vmpc_seq)
if P:
    cyc = vmpc_seq[-P:]
    print(f"[+] LOOP CYCLE period={P} bytecode-PCs (hex offsets):")
    print("   ", [hex(x) for x in cyc])
else:
    print("[+] no clean period; last 40 VM-PCs:", [hex(x) for x in vmpc_seq[-40:]])
# diff regfile snapshots at loop-start to find the loop counter (changing) vs constants
if len(regfile_at) >= 3:
    snaps = [regfile_at[i] for i in sorted(regfile_at)]
    print(f"[+] regfile[qword] evolution across {len(snaps)} loop iterations (only CHANGING slots):")
    for i in range(32):
        vals = [s[i] for s in snaps]
        if len(set(vals)) > 1:
            print(f"    R[{i:2d}]: " + " -> ".join(hex(v) for v in vals))
    print("[+] CONSTANT slots (candidate loop-limit/target):")
    for i in range(32):
        vals = [s[i] for s in snaps]
        if len(set(vals)) == 1 and vals[0] not in (0,) and vals[0] < 0x100000000:
            print(f"    R[{i:2d}] = {hex(vals[0])}")
# top memory addresses read in the loop (the spin-wait condition candidates)
print("[+] TOP loop memory-reads (addr : count : current value):")
for a, cnt in memreads.most_common(8):
    print(f"    {hex(a)} (off {hex(a-BASE) if BASE<=a<BASE+0x200000 else '-'}) x{cnt} = {hex(memread_vals.get(a,0))}")
print("[+] TOP loop memory-WRITES (addr : count : value-sequence) — counter candidates:")
for a, cnt in memwrites.most_common(12):
    seq = memwrite_seq.get(a, [])
    off = hex(a-BASE) if BASE<=a<BASE+0x200000 else ('stack' if 0x7834000000<=a<0x7835000000 else '-')
    print(f"    {hex(a)} (off {off}) x{cnt} = {[hex(v) for v in seq]}")
print(f"[+] emu stopped: {err}; blocks={dispatch['n']}; unmapped_pages={len(missing)}")
# show last blocks + faulting pc + disasm
try:
    fpc = uc.reg_read(UC_ARM64_REG_PC)
    print(f"[dbg] fault pc={hex(fpc)} (off {hex(fpc-BASE) if BASE<=fpc<BASE+0x200000 else 'OUT'})")
    print("[dbg] last 12 block addrs:", [hex(a-BASE) if BASE<=a<BASE+0x200000 else hex(a) for a in trace[-12:]])
    # disasm around fault if in-image
    if BASE <= fpc < BASE+0x200000:
        code = uc.mem_read(fpc, 32)
        for ins in md.disasm(bytes(code), fpc):
            print(f"    {hex(ins.address-BASE)}: {ins.mnemonic} {ins.op_str}")
            break
    for r in ['x15','x16','x17','x0']:
        print(f"    {r}={hex(uc.reg_read(REGMAP.get(r, {'x15':UC_ARM64_REG_X15,'x16':UC_ARM64_REG_X16,'x17':UC_ARM64_REG_X17,'x0':UC_ARM64_REG_X0}[r]))) }")
except Exception as e:
    print("[dbg] err", e)

# 6. search all mapped memory for the captured slot16 values (raw / ^0xed / reversed)
def read_all():
    chunks = {}
    for m in sorted(set(mapped)):
        try: chunks[m] = uc.mem_read(m, 0x1000)
        except: pass
    return chunks
chunks = read_all()
def find(needle):
    for m, b in chunks.items():
        i = b.find(needle)
        if i >= 0: return m + i
    return -1

print("\n=== search for captured slot16 in replayed memory ===")
hits = 0
for hexv in SLOTS:
    b = bytes.fromhex(hexv)
    for vn, nd in (("RAW", b), ("XOR0xED", bytes(x^0xed for x in b)), ("REV", b[::-1])):
        at = find(nd)
        if at >= 0:
            print(f"  [HIT] {hexv} as {vn} @ {hex(at)}")
            hits += 1; break
print(f"\n{hits}/{len(SLOTS)} captured slot16 reproduced in replayed VM memory")

# BIT-EXACT VERIFY (0x186600 replay): the 4 SM3-IV words must appear in replayed memory (regfile @x24).
print("\n=== SM3-IV bit-exact verify (for 0x186600 replay) ===")
IV_WORDS = ["6f168073b9b21449","d742241700068ada","bc306fa9aa383116","4dee8de34e0efbb0"]
ivhit=0
for w in IV_WORDS:
    b=bytes.fromhex(w); at=find(b)
    if at>=0: print(f"  [IV-HIT] {w} @ {hex(at)}"); ivhit+=1
    else: print(f"  [IV-MISS] {w}")
print(f"{ivhit}/4 SM3-IV words reproduced  => {'BIT-EXACT ✓' if ivhit==4 else 'partial/no'}")

# BIT-EXACT: compare replay's final regfile @captured-x24 to the LIVE epilogue output regfile (0x186420 verify)
if ENT.get("outrf"):
    x24 = int(ENT["regs"]["x24"], 16)
    try:
        rf_replay = bytes(uc.mem_read(x24, 256))
        rf_live = bytes.fromhex(ENT["outrf"])
        match = sum(1 for i in range(0,256,8) if rf_replay[i:i+8]==rf_live[i:i+8])
        print(f"\n=== BIT-EXACT regfile compare (replay vs LIVE epilogue) @x24={hex(x24)} ===")
        print(f"  {match}/32 registers match  => {'>>> BIT-EXACT <<<' if match>=30 else 'MISMATCH ('+str(match)+'/32)'}")
        for i in range(0,256,8):
            if rf_replay[i:i+8]!=rf_live[i:i+8]:
                print(f"    r{i//8}: replay={rf_replay[i:i+8].hex()} live={rf_live[i:i+8].hex()}")
    except Exception as e:
        print("[!] regfile compare err", e)

# inspect the VM output buffers (caller set x1=sp, x4=sp+0x10 at entry) + what the VM wrote
print("\n=== VM output-buffer inspection (args x1/x4 captured at entry) ===")
for rn in ("x1", "x2", "x4", "x0", "x8"):
    if rn in ENT["regs"]:
        av = int(ENT["regs"][rn], 16)
        try:
            data = bytes(uc.mem_read(av, 64))
            print(f"  [{rn}=0x{av:x}]: {data[:48].hex()}")
        except Exception:
            print(f"  [{rn}=0x{av:x}]: unmapped")
# also: did the VM write any of the expected slot16 anywhere (already searched); show blocks/pcs summary
print(f"[i] VM ran {dispatch['n']} blocks, {len(vmpcs)} distinct bytecode-PCs (short={len(vmpcs)<50})")
if hits == 0:
    print("[-] none reproduced yet — likely need more captured memory (unmapped pages read as zero)")
    top = sorted(missing.items(), key=lambda x: -x[1])[:10]
    print("    top unmapped pages (need capture):", [hex(p) for p, c in top])
