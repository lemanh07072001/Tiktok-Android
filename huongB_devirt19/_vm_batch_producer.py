#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_batch_producer.py — for each of the 41 native bl-0x52924 VM-invocation sites, find its function
# entry, run it in a FRESH unicorn (full dump image), and record: reached-RET, insn count, self-contained
# (fault pages), 16-byte heap/data writes, and the x4-output buffer + its entropy. A self-contained fn that
# emits a 16-byte high-entropy value is a slot16-producer candidate. Run under Python311.
import json, struct, math
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm64 import *

META = json.load(open("_code_dump_full_meta.json")); BASE = int(META["base"], 16)
IMG  = open("_code_dump_full.bin", "rb").read(); IMGSZ = len(IMG)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

SITES = [0x4fc1c,0x5f1dc,0x76600,0x766e0,0x768ec,0x817b8,0x818ec,0x819f0,0x81f48,0x936f4,0x93860,
 0x95a98,0x962f4,0x9a1fc,0x9a274,0x9a908,0x9b3d8,0x9fd70,0x9ff18,0xb5bcc,0xb5cac,0xb5d30,0xb5dbc,
 0xb5f2c,0xbc1c0,0xbd3a4,0xc1e6c,0xcff9c,0xe04ac,0xe0ec0,0x10ac80,0x116bc8,0x116c54,0x117e6c,
 0x1279a0,0x1384e4,0x1426c0,0x144b7c,0x144c04,0x144cf8,0x145ef8]

def find_entry(site):
    """scan backward for the function prologue that cleanly disassembles through to `site`."""
    best = None
    for e in range(site-4, site-0x800, -4):
        try:
            ins = list(md.disasm(IMG[e:site+4], BASE+e))
        except Exception:
            continue
        if not ins: continue
        # must reach the site as an instruction boundary, cleanly
        addrs = {i.address-BASE for i in ins}
        if site not in addrs: continue
        m0 = ins[0].mnemonic; op0 = ins[0].op_str
        # prologue signatures
        if (m0=='sub' and op0.startswith('sp, sp,')) or \
           (m0 in ('stp',) and ('[sp, #-' in op0) and op0.endswith('!')):
            best = e
    return best

def entropy(b):
    if not b: return 0
    from collections import Counter
    c = Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def run_entry(entry):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mapped=set()
    def ensure(va,sz=1):
        for a in range(va& ~0xfff, (va+sz+0xfff)&~0xfff,0x1000):
            if a not in mapped: uc.mem_map(a,0x1000,UC_PROT_ALL); mapped.add(a)
    for a in range(BASE&~0xfff,(BASE+IMGSZ+0xfff)&~0xfff,0x1000): uc.mem_map(a,0x1000,UC_PROT_ALL); mapped.add(a)
    uc.mem_write(BASE, IMG)
    STUB=0x200000000; HEAP=0x300000000
    uc.mem_map(STUB,0x10000,UC_PROT_ALL); mapped.add(STUB)
    for a in range(HEAP,HEAP+0x800000,0x1000): uc.mem_map(a,0x1000,UC_PROT_ALL); mapped.add(a)
    heap={"p":HEAP+0x1000}
    def alloc(n): p=heap["p"]; heap["p"]=(p+(n or 16)+15)&~15; return p
    elf=ELFFile(open("bin/libmetasec_ov.so","rb")); dynsym=elf.get_section_by_name(".dynsym"); imports=[]
    for sec in elf.iter_sections():
        if sec.header["sh_type"]=="SHT_RELA" and "plt" in sec.name:
            for r in sec.iter_relocations():
                nm=dynsym.get_symbol(r["r_info_sym"]).name; idx=len(imports); imports.append(nm)
                sent=STUB+idx*4; uc.mem_write(BASE+r["r_offset"],struct.pack("<Q",sent)); uc.mem_write(sent,struct.pack("<I",0xd65f03c0))
    def do_imp(name):
        x=[uc.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]; ret=0
        try:
            if name.endswith(("memcpy","memmove")) or name in ("memcpy","memmove"):
                d,s,n=x;
                if n and n<0x100000: ensure(d,n); uc.mem_write(d,bytes(uc.mem_read(s,n)))
                ret=d
            elif name=="memset":
                d,c,n=x
                if n and n<0x100000: ensure(d,n); uc.mem_write(d,bytes([c&0xff])*n)
                ret=d
            elif name in ("malloc","valloc","aligned_alloc","_Znwm","_Znam"): ret=alloc(x[0] if 0<x[0]<0x400000 else 0x1000)
            elif name=="calloc":
                n=(x[0]*x[1]) or 0x100; ret=alloc(n if n<0x400000 else 0x1000); uc.mem_write(ret,b"\x00"*min(n,0x1000))
            else: ret=0
        except Exception: ret=0
        uc.reg_write(UC_ARM64_REG_X0,ret&(2**64-1)); uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
    def on_stub(uc,addr,sz,d):
        if STUB<=addr<STUB+len(imports)*4: do_imp(imports[(addr-STUB)//4])
    uc.hook_add(UC_HOOK_CODE,on_stub,begin=STUB,end=STUB+0x10000)
    TLS=0x400000000; uc.mem_map(TLS,0x1000,UC_PROT_ALL); mapped.add(TLS)
    uc.mem_write(TLS+0x28,struct.pack("<Q",0xC0FFEE12)); uc.reg_write(UC_ARM64_REG_TPIDR_EL0,TLS)
    STK=0x700000000
    for a in range(STK-0x80000,STK,0x1000): uc.mem_map(a,0x1000,UC_PROT_ALL); mapped.add(a)
    uc.reg_write(UC_ARM64_REG_SP,STK-0x8000)
    SENT=0x123400000; uc.mem_map(SENT&~0xfff,0x1000,UC_PROT_ALL); mapped.add(SENT&~0xfff); uc.reg_write(UC_ARM64_REG_LR,SENT)
    # x0..x4 = fresh heap objects (so a `this`/arg deref lands on mapped zero memory, not fault)
    for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4):
        uc.reg_write(r, alloc(0x400))
    faults={}
    def on_unm(uc,acc,addr,sz,val,d):
        pg=addr&~0xfff
        if pg not in mapped:
            try: uc.mem_map(pg,0x1000,UC_PROT_ALL); mapped.add(pg)
            except: return False
        faults[pg]=faults.get(pg,0)+1; return True
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED,on_unm)
    writes=[]
    def on_wr(uc,acc,addr,sz,val,d):
        if HEAP<=addr<HEAP+0x800000: writes.append((addr,sz,val))
        return True
    uc.hook_add(UC_HOOK_MEM_WRITE,on_wr)
    ni={"n":0}
    def on_c(uc,addr,sz,d): ni["n"]+=1
    uc.hook_add(UC_HOOK_CODE,on_c,begin=BASE,end=BASE+IMGSZ)
    reached=False
    try:
        uc.emu_start(BASE+entry,SENT,count=30000); reached=True
    except UcError: pass
    # collect 16-byte contiguous heap writes (2 adjacent 8-byte or a 16 write)
    hw={}
    for addr,sz,val in writes: hw.setdefault(addr,sz)
    blobs=[]
    for addr in sorted(hw):
        if addr+8 in hw:  # adjacent 8+8 = 16 bytes
            try: b=bytes(uc.mem_read(addr,16)); blobs.append((addr,b))
            except: pass
    blobs=[(a,b) for a,b in blobs if len(set(b))>=8]  # high-ish entropy
    return dict(reached=reached, insn=ni["n"], faults=len(faults), nwrite=len(writes),
               blobs=[(hex(a-HEAP), b.hex(), round(entropy(b),2)) for a,b in blobs[:4]])

if __name__ == "__main__":
    import sys
    fo = open("_batch_producer_out.txt","w")
    hdr = "site      entry     reached insn    faults writes  16B-blobs(entropy)"
    print(hdr); fo.write(hdr+"\n"); fo.flush()
    for s in SITES:
        e = find_entry(s)
        if e is None:
            line="0x%06x  <no-entry>"%s
        else:
            try:
                r = run_entry(e)
                tag = ' <<< 16B-BLOB' if r["blobs"] else ''
                line="0x%06x  0x%06x  %-5s %-7d %-6d %-6d %s%s"%(
                    s, e, r["reached"], r["insn"], r["faults"], r["nwrite"], r["blobs"][:2], tag)
            except Exception as ex:
                line="0x%06x  0x%06x  ERR %s"%(s,e,str(ex)[:40])
        print(line, flush=True); fo.write(line+"\n"); fo.flush()
    fo.close()
