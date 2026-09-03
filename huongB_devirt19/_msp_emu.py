#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _msp_emu.py — Decrypt a .msp/.mss buffer OFFLINE by emulating the metasec
# decrypt worker fn_0x12f290 in Unicorn. No phone, no anti-frida.
#
# Worker signature (from disasm of 0x12f278 thunk -> 0x12f290):
#   void worker(std::string* out /*x0*/, Desc* in /*x1*/, int mode /*x2=1*/)
#   Desc { u32 type@0; s32 len@4; void* data@8 }  (len<0 => skip/empty)
#   out is a libc++ std::string (sret); plaintext lands in *out.
#
# We build a Desc pointing at the raw file bytes, call the worker, read *out.
import os, sys, struct
os.chdir(os.path.dirname(os.path.abspath(__file__)))
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *

SO="bin/libmetasec_ov.so"
WORKER=0x12f290
PLT_START=0x30390; PLT_END=0x30390+0xa70
PLT_MAP={0x30610:"malloc",0x305d0:"calloc",0x30760:"realloc",0x30590:"free",
    0x303d0:"memcpy",0x30690:"memmove",0x30930:"memset",0x306d0:"strlen",
    0x30600:"strcmp",0x307d0:"strncmp",0x308e0:"strcpy",0x30450:"strncpy",
    0x304c0:"_Znam",0x30480:"_ZdlPv",0x30900:"_ZdaPv",0x309d0:"abort",
    0x30680:"cxa_guard_release",0x30dd0:"cxa_guard_acquire",0x30420:"memchr"}
PLT_HANDLERS={k:v for k,v in PLT_MAP.items() if PLT_START<=k<PLT_END}

def load_segments(uc, so, base):
    e_phoff=struct.unpack_from("<Q",so,0x20)[0]
    e_phnum=struct.unpack_from("<H",so,0x38)[0]
    e_phent=struct.unpack_from("<H",so,0x36)[0]
    for i in range(e_phnum):
        off=e_phoff+i*e_phent
        if struct.unpack_from("<I",so,off)[0]!=1: continue
        p_off=struct.unpack_from("<Q",so,off+8)[0]
        p_va =struct.unpack_from("<Q",so,off+16)[0]
        p_fsz=struct.unpack_from("<Q",so,off+32)[0]
        p_msz=struct.unpack_from("<Q",so,off+40)[0]
        start=(base+p_va)&~0xfff
        size=((base+p_va+p_msz-start)+0xfff)&~0xfff
        try: uc.mem_map(start,size,UC_PROT_ALL)
        except UcError: pass
        if p_fsz: uc.mem_write(base+p_va, so[p_off:p_off+p_fsz])

def apply_relocs(uc, so, base):
    e_shoff=struct.unpack_from("<Q",so,0x28)[0]
    e_shnum=struct.unpack_from("<H",so,0x3c)[0]
    e_shent=struct.unpack_from("<H",so,0x3a)[0]
    for i in range(e_shnum):
        b=e_shoff+i*e_shent
        if struct.unpack_from("<I",so,b+4)[0]!=4: continue
        off=struct.unpack_from("<Q",so,b+0x18)[0]
        sz =struct.unpack_from("<Q",so,b+0x20)[0]
        for j in range(0,sz,24):
            r_off=struct.unpack_from("<Q",so,off+j)[0]
            r_info=struct.unpack_from("<Q",so,off+j+8)[0]
            r_add=struct.unpack_from("<q",so,off+j+16)[0]
            if (r_info&0xffffffff)==1027:
                try: uc.mem_write(base+r_off,struct.pack("<Q",(base+r_add)&0xffffffffffffffff))
                except UcError: pass

def read_cxx_string(uc, p):
    b0=uc.mem_read(p,1)[0]
    if (b0&1)==0:
        ln=b0>>1
        return bytes(uc.mem_read(p+1,ln)) if ln else b""
    ln=struct.unpack_from("<Q",uc.mem_read(p+8,8),0)[0]
    dat=struct.unpack_from("<Q",uc.mem_read(p+16,8),0)[0]
    return bytes(uc.mem_read(dat,min(ln,4096))) if ln and dat else b""

def decrypt(fname, verbose=False):
    so=open(SO,"rb").read()
    data=open(fname,"rb").read()
    base=0x400000000
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    load_segments(uc,so,base); apply_relocs(uc,so,base)
    # stack
    sp=base+0x10000000; uc.mem_map(sp-0x100000,0x200000,UC_PROT_ALL); sp=sp
    # heap (bump)
    heap=base+0x20000000; uc.mem_map(heap,0x2000000,UC_PROT_ALL); hp=[heap]; hend=heap+0x2000000
    # scratch for Desc + input data + out string
    scratch=base+0x30000000; uc.mem_map(scratch,0x100000,UC_PROT_ALL)
    in_data=scratch; uc.mem_write(in_data,data)
    desc=scratch+0x10000
    uc.mem_write(desc, struct.pack("<IiQ", 0, len(data), in_data))  # {type=0,len,data}
    out=scratch+0x20000
    uc.mem_write(out, b"\x00"*32)  # empty libc++ string (SSO, len 0)
    # tls base for tpidr_el0 [x23+0x28] stack canary read
    tls=base+0x40000000; uc.mem_map(tls,0x10000,UC_PROT_ALL)
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, tls)

    def plt_hook(uc,addr,size,ud):
        off=addr-base; fn=PLT_HANDLERS.get(off)
        lr=uc.reg_read(UC_ARM64_REG_LR)
        x0=uc.reg_read(UC_ARM64_REG_X0);x1=uc.reg_read(UC_ARM64_REG_X1);x2=uc.reg_read(UC_ARM64_REG_X2)
        def ret(v=0):uc.reg_write(UC_ARM64_REG_X0,v);uc.reg_write(UC_ARM64_REG_PC,lr)
        if fn is None: return ret(0)
        if fn in("malloc","_Znam"):
            n=(x0 or 8+15)&~15; p=hp[0]
            if p+n>hend: return ret(0)
            hp[0]=p+n; return ret(p)
        if fn=="calloc":
            n=((x0*x1) or 8+15)&~15; p=hp[0]
            if p+n>hend: return ret(0)
            hp[0]=p+n
            try: uc.mem_write(p,b"\x00"*n)
            except UcError: pass
            return ret(p)
        if fn=="realloc":
            n=(x1 or 8+15)&~15; p=hp[0]; hp[0]=p+n
            if x0:
                try: uc.mem_write(p,bytes(uc.mem_read(x0,min(n,4096))))
                except UcError: pass
            return ret(p)
        if fn in("memcpy","memmove"):
            if x2>0:
                try: uc.mem_write(x0,bytes(uc.mem_read(x1,x2)))
                except UcError: pass
            return ret(x0)
        if fn=="memset":
            if x2>0:
                try: uc.mem_write(x0,bytes([x1&0xff]*x2))
                except UcError: pass
            return ret(x0)
        if fn=="strlen":
            try:
                d=uc.mem_read(x0,4096); n=bytes(d).find(b"\x00"); return ret(n if n>=0 else 4096)
            except UcError: return ret(0)
        if fn=="cxa_guard_acquire": return ret(1)
        if fn=="abort":
            uc.emu_stop(); return
        return ret(0)
    uc.hook_add(UC_HOOK_CODE,plt_hook,begin=base+PLT_START,end=base+PLT_END)

    def on_unmapped(uc,access,addr,size,val,ud):
        try: uc.mem_map(addr&~0xfff,0x1000,UC_PROT_ALL); return True
        except UcError: return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED,on_unmapped)

    # optional trace
    steps=[0]
    if verbose:
        def tr(uc,addr,size,ud):
            steps[0]+=1
            if steps[0]<=40: print(f"    pc=0x{addr-base:x}")
        uc.hook_add(UC_HOOK_CODE,tr)

    # set up call: x0=out, x1=desc, x2=mode(1), lr=magic return
    RET=base+0x1000  # a mapped addr; we stop when pc hits it
    uc.reg_write(UC_ARM64_REG_SP,sp)
    uc.reg_write(UC_ARM64_REG_X0,out)
    uc.reg_write(UC_ARM64_REG_X1,desc)
    uc.reg_write(UC_ARM64_REG_X2,1)
    uc.reg_write(UC_ARM64_REG_LR,RET)
    try:
        uc.emu_start(base+WORKER, RET, count=2000000)
    except UcError as e:
        print(f"  [{os.path.basename(fname)}] emu err: {e} after {steps[0]} steps")
        return None
    plain=read_cxx_string(uc,out)
    return plain

if __name__=="__main__":
    import glob
    files=sys.argv[1:] or sorted(glob.glob("psk_files/*.bin"))
    for f in files:
        try:
            pt=decrypt(f)
        except Exception as e:
            print(f"  [{os.path.basename(f)}] EXC {e}"); continue
        if pt is None: continue
        printable=sum(1 for b in pt if 32<=b<127)
        pct=printable/len(pt)*100 if pt else 0
        show=pt[:96]
        asc="".join(chr(b) if 32<=b<127 else "." for b in show)
        print(f"  [{os.path.basename(f):22s}] plain={len(pt)}B {pct:.0f}%pr  {pt[:32].hex()}")
        print(f"       ascii: {asc}")
