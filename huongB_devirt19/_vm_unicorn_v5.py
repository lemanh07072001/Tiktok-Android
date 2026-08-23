#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_unicorn_v5.py — WARM-CONTINUE from the atomic_capture point.
#
# v4 was wrong: it cold-started at 0x17bc6c but never wrote the captured
# regfile into [x24], so the VM ran on a zero regfile and took the end-
# sentinel branch (op=44 -> 0x5d464 ret) after 21 dispatches.
#
# v5 restores the EXACT captured state:
#   - [x23] <- capture bcptr (base+0x1919f4)
#   - [x24..+256] <- captured regfile (32 qwords)
#   - stack image written at sp
# then runs forward to the VM's ret, tracing dispatches and dumping the
# regfile + any 16-byte output that emerges (candidate slot16).
import os, json, struct
os.chdir(os.path.dirname(os.path.abspath(__file__)))
import _vm_unicorn_v4 as V
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE, UcError)
from unicorn.arm64_const import *

def h2i(s): return int(s,16) if s not in (None,"","NULL") else 0

def main():
    so = open(V.SO,"rb").read()
    cap = V.load_capture(0)
    # setup() maps segments, relocs, stack, heap, seeds cpu regs + stack image.
    uc, base = V.setup(so, cap)

    x23 = h2i(cap["cpur"]["x23"])
    x24 = h2i(cap["cpur"]["x24"])
    bcptr_cap = int(cap["bcPtr"],16)          # 0x6f3ed919f4 = base+0x1919f4

    # --- the two fixes ---
    uc.mem_write(x23, struct.pack("<Q", bcptr_cap))          # real bcptr
    regfile = bytes.fromhex(json.load(open(V.CAPTURE_FILE, encoding="utf-8"))[0]["regfile"])
    uc.mem_write(x24, regfile)                                # real regfile (256B)
    print(f"[v5] *x23 = 0x{bcptr_cap:x} (base+0x{bcptr_cap-base:x})")
    print(f"[v5] regfile[{len(regfile)}B] written to 0x{x24:x}")

    # trace + capture-writes-of-16-bytes-of-hex-looking output
    ic=[0]; disp=[0]; last_pc=[0]
    heap_ptr=[base+0x300000]; heap_end=base+0x300000+0x1000000
    def hook(uc, addr, size, ud):
        ic[0]+=1; last_pc[0]=addr
        code = uc.mem_read(addr,size)
        if struct.unpack_from("<I",code,0)[0]==0xd61f01e0:  # br x15
            disp[0]+=1
            x15=uc.reg_read(UC_ARM64_REG_X15); x23r=uc.reg_read(UC_ARM64_REG_X23)
            try:
                bc=struct.unpack_from("<Q",uc.mem_read(x23r,8))[0]
                ow=struct.unpack_from("<I",uc.mem_read(bc,4))[0]
                op=ow&0x3f; opnd=struct.unpack_from("<I",uc.mem_read(bc+4,4))[0]
                print(f"  [D#{disp[0]:3d}] op={op:2d} bc=0x{(bc-base)&0xffffffffffffffff:x} "
                      f"ow=0x{ow:08x} opnd=0x{opnd:08x} h=0x{(x15-base)&0xffffffffffffffff:x}")
            except Exception as e:
                print(f"  [D#{disp[0]:3d}] bcptr read err {e}")
        if ic[0]>200000: uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)

    def on_unmapped(uc, access, addr, size, val, ud):
        try: uc.mem_map(addr&~0xfff, 0x1000, UC_PROT_ALL); return True
        except UcError: return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    # PLT emulation — reuse v4's plt_hook by importing its run()? It's inline.
    # Simplest: install the same PLT hook via v4.run internals is messy; re-map.
    V_run_plt(uc, base, heap_ptr, heap_end)

    entry = base + V.VM_ENTRY
    print(f"[v5] emulate from VM_ENTRY 0x{entry:x}\n")
    try:
        uc.emu_start(entry, 0, count=0)   # run until ret (LR) or stop
    except UcError as e:
        print(f"\n[v5] emu stopped: {e} at insn #{ic[0]} pc~0x{(last_pc[0]-base)&0xffffffffffffffff:x}")

    print(f"\n[v5] {ic[0]} insns, {disp[0]} dispatches")
    print("\n=== regfile after ===")
    for i in range(32):
        v=struct.unpack_from("<Q",uc.mem_read(x24+i*8,8))[0]
        if v: print(f"  R[{i:2d}] = 0x{v:016x}")

    # scan heap for a 16-byte region that looks like slot16 (nonzero, high entropy)
    print("\n=== heap scan for 16-byte candidates ===")
    scanned = uc.mem_read(base+0x300000, min(heap_ptr[0]-(base+0x300000), 0x4000))
    for i in range(0, len(scanned)-16, 4):
        c = bytes(scanned[i:i+16])
        if c==b'\x00'*16: continue
        uniq=len(set(c))
        if uniq>=12:
            print(f"  heap+0x{i:04x}: {c.hex()}")

def V_run_plt(uc, base, heap_ptr, heap_end):
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_PC
    guard={}
    def plt(uc, addr, size, ud):
        off=addr-base; fn=V.PLT_HANDLERS.get(off)
        lr=uc.reg_read(UC_ARM64_REG_LR); x0=uc.reg_read(UC_ARM64_REG_X0)
        x1=uc.reg_read(UC_ARM64_REG_X1); x2=uc.reg_read(UC_ARM64_REG_X2)
        def ret(v=0): uc.reg_write(UC_ARM64_REG_X0,v); uc.reg_write(UC_ARM64_REG_PC,lr)
        if fn is None: return ret(0)
        if fn in ("malloc","calloc","realloc","_Znam","_Znwm"):
            n=x0 or 8
            if fn=="calloc": n=(x0*x1) or 8
            if fn=="realloc": n=x1 or 8
            n=(n+15)&~15; p=heap_ptr[0]
            if p+n>heap_end: return ret(0)
            heap_ptr[0]=p+n
            if fn=="calloc":
                try: uc.mem_write(p,b'\x00'*n)
                except UcError: pass
            return ret(p)
        if fn=="memcpy" or fn=="memmove":
            if x2>0:
                try: uc.mem_write(x0, bytes(uc.mem_read(x1,x2)))
                except UcError: pass
            return ret(x0)
        if fn=="memset":
            if x2>0:
                try: uc.mem_write(x0, bytes([x1&0xff]*x2))
                except UcError: pass
            return ret(x0)
        if fn=="cxa_guard_acquire":
            if x0 in guard: return ret(0)
            guard[x0]=1
            try: uc.mem_write(x0,b'\x01'+b'\x00'*7)
            except UcError: pass
            return ret(1)
        if fn=="cxa_guard_release":
            guard[x0]=2; return ret(0)
        if fn=="strlen":
            try:
                d=uc.mem_read(x0,4096); n=d.find(b'\x00'); return ret(n if n>=0 else 4096)
            except UcError: return ret(0)
        if fn=="abort": print("  [ABORT]"); uc.emu_stop(); return
        return ret(0)
    uc.hook_add(UC_HOOK_CODE, plt, begin=base+V.PLT_START, end=base+V.PLT_END)

if __name__=="__main__":
    main()
