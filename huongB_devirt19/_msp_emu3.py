#!/usr/bin/env python3
# msp_emu3.py — run .init_array ctors, then decrypt worker. Offline.
import os,sys,struct,json,collections
from unicorn import *
from unicorn.arm64_const import *
SO_PATH="bin/libmetasec_ov.so"
WORKER=0x12f290
so=open(SO_PATH,"rb").read()
base=0x400000000
PLT={int(k,16):v for k,v in json.load(open("_plt_map.json")).items()}
PLT_LO=min(PLT);PLT_HI=max(PLT)+16
def u16(o):return struct.unpack_from("<H",so,o)[0]
def u32(o):return struct.unpack_from("<I",so,o)[0]
def u64(o):return struct.unpack_from("<Q",so,o)[0]
def secs():
    e_shoff=u64(0x28);e_shnum=u16(0x3c);e_shent=u16(0x3a);e_shstrndx=u16(0x3e)
    t=[]
    for i in range(e_shnum):
        b=e_shoff+i*e_shent; t.append((u32(b),u64(b+0x10),u64(b+0x18),u64(b+0x20)))
    shstr=t[e_shstrndx][2]; d={}
    for nm,addr,off,size in t:
        e=so.find(b'\0',shstr+nm); d[so[shstr+nm:e].decode()]=(addr,off,size)
    return d
SEC=secs()
def init_array():
    a,o,s=SEC[".init_array"]; return [u64(o+i*8) for i in range(s//8)]
def setup(uc):
    e_phoff=u64(0x20);e_phnum=u16(0x38);e_phent=u16(0x36)
    for i in range(e_phnum):
        off=e_phoff+i*e_phent
        if u32(off)!=1: continue
        p_off=u64(off+8);p_va=u64(off+16);p_fsz=u64(off+32);p_msz=u64(off+40)
        st=(base+p_va)&~0xfff; sz=((base+p_va+p_msz-st)+0xfff)&~0xfff
        try: uc.mem_map(st,sz,UC_PROT_ALL)
        except UcError: pass
        if p_fsz: uc.mem_write(base+p_va,so[p_off:p_off+p_fsz])
    e_shoff=u64(0x28);e_shnum=u16(0x3c);e_shent=u16(0x3a)
    for i in range(e_shnum):
        b=e_shoff+i*e_shent
        if u32(b+4)!=4: continue
        off=u64(b+0x18);sz=u64(b+0x20)
        for j in range(0,sz,24):
            r_off=u64(off+j);r_info=u64(off+j+8);r_add=struct.unpack_from("<q",so,off+j+16)[0]
            if (r_info&0xffffffff)==1027:
                try: uc.mem_write(base+r_off,struct.pack("<Q",(base+r_add)&0xffffffffffffffff))
                except UcError: pass
def read_cxx_string(uc,p):
    b0=uc.mem_read(p,1)[0]
    if (b0&1)==0:
        ln=b0>>1; return bytes(uc.mem_read(p+1,ln)) if ln else b""
    ln=struct.unpack_from("<Q",uc.mem_read(p+8,8),0)[0]; dat=struct.unpack_from("<Q",uc.mem_read(p+16,8),0)[0]
    return bytes(uc.mem_read(dat,min(ln,65536))) if ln and dat else b""

class Emu:
    def __init__(self):
        self.uc=uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        setup(uc)
        uc.mem_map(base+0x0ff00000,0x400000,UC_PROT_ALL) # stack region
        self.sp0=base+0x10200000
        self.heap=base+0x20000000; uc.mem_map(self.heap,0x10000000,UC_PROT_ALL); self.hp=self.heap+0x100; self.hend=self.heap+0x10000000
        uc.mem_map(base+0x30000000,0x400000,UC_PROT_ALL) # scratch
        uc.mem_map(base+0x40000000,0x20000,UC_PROT_ALL)  # tls
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0,base+0x40001000)
        uc.mem_map(base,0x1000,UC_PROT_ALL) if False else None
        try: uc.mem_map(base,0x2000,UC_PROT_ALL)
        except UcError: pass
        self.RET=base+0x800
        self.unhandled=collections.Counter()
        uc.hook_add(UC_HOOK_CODE,self.plt,begin=base+PLT_LO,end=base+PLT_HI)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED,self.unmapped)
    def alloc(self,n):
        n=((n or 16)+15)&~15; p=self.hp
        if p+n>self.hend: return 0
        self.hp=p+n; return p
    def unmapped(self,uc,acc,addr,size,val,ud):
        try: uc.mem_map(addr&~0xfff,0x2000,UC_PROT_ALL); return True
        except UcError: return False
    def plt(self,uc,addr,size,ud):
        fn=PLT.get(addr-base)
        if fn is None: return
        lr=uc.reg_read(UC_ARM64_REG_LR)
        x0=uc.reg_read(UC_ARM64_REG_X0);x1=uc.reg_read(UC_ARM64_REG_X1);x2=uc.reg_read(UC_ARM64_REG_X2)
        def ret(v=0): uc.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff); uc.reg_write(UC_ARM64_REG_PC,lr)
        def rd(a,n):
            try:return bytes(uc.mem_read(a,n))
            except UcError:return b""
        if fn in("malloc","_Znwm","_Znam"): return ret(self.alloc(x0))
        if fn=="calloc":
            p=self.alloc(x0*x1)
            if p: uc.mem_write(p,b"\x00"*(((x0*x1 or 16)+15)&~15))
            return ret(p)
        if fn=="realloc":
            p=self.alloc(x1)
            if x0 and p: uc.mem_write(p,rd(x0,min(x1,65536)))
            return ret(p)
        if fn=="strdup":
            s=rd(x0,65536); n=s.find(b"\x00"); s=s[:n if n>=0 else 0]; p=self.alloc(len(s)+1); uc.mem_write(p,s+b"\x00"); return ret(p)
        if fn in("free","_ZdlPv","_ZdaPv"): return ret(0)
        if fn in("memcpy","memmove","__memcpy_chk"):
            if x2>0: uc.mem_write(x0,rd(x1,x2))
            return ret(x0)
        if fn in("memset","__memset_chk"):
            if x2>0: uc.mem_write(x0,bytes([x1&0xff])*x2)
            return ret(x0)
        if fn=="memchr":
            d=rd(x0,x2); i=d.find(bytes([x1&0xff])); return ret(x0+i if i>=0 else 0)
        if fn in("strlen","__strlen_chk"):
            d=rd(x0,65536); n=d.find(b"\x00"); return ret(n if n>=0 else 0)
        if fn in("strcmp","strncmp"):
            a=rd(x0,256);b=rd(x1,256); a=a[:a.find(b"\x00")];b=b[:b.find(b"\x00")]; return ret(0 if a==b else 1)
        if fn in("strcpy","strncpy"):
            s=rd(x1,4096)
            if fn=="strncpy": s=s[:x2]
            else: n=s.find(b"\x00"); s=s[:n if n>=0 else 0]+b"\x00"
            uc.mem_write(x0,s); return ret(x0)
        if fn=="strchr":
            d=rd(x0,65536); n=d.find(b"\x00"); d=d[:n if n>=0 else 0]; i=d.find(bytes([x1&0xff])); return ret(x0+i if i>=0 else 0)
        if fn in("strtoull","strtol","strtoul"):
            d=rd(x0,64).split(b"\x00")[0].strip()
            try:v=int(d,0)
            except:v=0
            return ret(v)
        if fn=="memcmp":
            a=rd(x0,x2);b=rd(x1,x2); return ret(0 if a==b else (1 if a>b else (1<<64)-1))
        if fn=="getpagesize": return ret(0x1000)
        if fn=="pthread_once":
            uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x1); return
        if fn=="_ZNSt6__ndk111__call_onceERVmPvPFvS2_E":
            uc.reg_write(UC_ARM64_REG_X0,x1); uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x2); return
        if fn=="__cxa_guard_acquire": return ret(1)
        if fn=="__cxa_guard_release": return ret(0)
        if fn=="pthread_self": return ret(base+0x40001000)
        if fn=="pthread_getspecific": return ret(0)
        if fn.startswith("pthread_") or "mutex" in fn or "shared_mutex" in fn or "condition_variable" in fn or "ios_base" in fn or fn.endswith("D1Ev") or fn.endswith("C1Ev") or fn.endswith("D2Ev"): return ret(0)
        if fn in("__cxa_atexit","atexit","__cxa_thread_atexit"): return ret(0)
        self.unhandled[fn]+=1; return ret(0)
    def call(self,pc,args=(),count=3000000):
        uc=self.uc
        for i,v in enumerate(args): uc.reg_write(UC_ARM64_REG_X0+i,v)
        uc.reg_write(UC_ARM64_REG_SP,self.sp0)
        uc.reg_write(UC_ARM64_REG_LR,self.RET)
        try:
            uc.emu_start(base+pc,self.RET,count=count); return None
        except UcError as e:
            return str(e)
    def run_init(self,verbose=False,limit=None):
        arr=init_array()
        done=0; fail=0
        for idx,fn in enumerate(arr):
            if limit and idx>=limit: break
            err=self.call(fn,(),count=2000000)
            pc=self.uc.reg_read(UC_ARM64_REG_PC)-base
            if pc!=(self.RET-base):
                fail+=1
                if verbose: print("  ctor[%d]=0x%x DID NOT return (pc=0x%x err=%s)"%(idx,fn,pc,err))
            else: done+=1
        return done,fail

if __name__=="__main__":
    files=sys.argv[1:] or ["cap.noindex/gt_live/.msp_092fde7a53a0274594af0984c7830fc0c13dc8bd"]
    e=Emu()
    d,f=e.run_init(verbose=True)
    print("init_array: %d ran-to-ret, %d did-not-return"%(d,f))
    for path in files:
        data=open(path,"rb").read()
        uc=e.uc
        scratch=base+0x30000000
        uc.mem_write(scratch,data)
        desc=scratch+0x100000; uc.mem_write(desc,struct.pack("<IiQ",0,len(data),scratch))
        out=scratch+0x180000; uc.mem_write(out,b"\x00"*32)
        err=e.call(WORKER,(out,desc,1),count=5000000)
        pc=uc.reg_read(UC_ARM64_REG_PC)-base
        plain=read_cxx_string(uc,out)
        pr=sum(1 for b in plain if 32<=b<127)
        print("[%s] worker pc=0x%x err=%s plain=%dB pr=%d%%"%(os.path.basename(path),pc,err,len(plain),(pr*100//len(plain)) if plain else 0))
        print("   head:",plain[:96])
    print("unhandled imports:",dict(e.unhandled))
