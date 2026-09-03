#!/usr/bin/env python3
# _mss_getter.py — full read-getter emulation for .mss, with STATEFUL pthread TLS
# + real once semantics + key_create, to get the lazy logger singleton to
# construct once instead of spinning (prior blocker, notes/56).
import sys, os, struct, importlib.util
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
_spec=importlib.util.spec_from_file_location("e3","_msp_emu3.py")
e3=importlib.util.module_from_spec(_spec); sys.argv=["x"]; _spec.loader.exec_module(e3)
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
    UC_ARM64_REG_LR,UC_ARM64_REG_PC)
base=e3.base
_orig_plt=e3.Emu.plt

def patched_plt(self,uc,addr,size,ud):
    fn=e3.PLT.get(addr-base)
    if fn is None: return
    if not hasattr(self,"tls"): self.tls={}; self.keys=1; self.once=set()
    lr=uc.reg_read(UC_ARM64_REG_LR)
    x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1)
    def ret(v=0): uc.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff); uc.reg_write(UC_ARM64_REG_PC,lr)
    if fn=="pthread_key_create":
        kid=self.keys; self.keys+=1
        try: uc.mem_write(x0,struct.pack("<I",kid))
        except Exception: pass
        self.tls[kid]=0; return ret(0)
    if fn=="pthread_key_delete": return ret(0)
    if fn=="pthread_setspecific":
        self.tls[x0&0xffffffff]=x1; return ret(0)
    if fn=="pthread_getspecific":
        return ret(self.tls.get(x0&0xffffffff,0))
    if fn=="pthread_once":
        if x0 in self.once: return ret(0)
        self.once.add(x0); uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x1); return
    if fn=="_ZNSt6__ndk111__call_onceERVmPvPFvS2_E":
        # __call_once(flag&, arg, fn) — run fn(arg) once
        x2=uc.reg_read(UC_ARM64_REG_X2)
        if x0 in self.once: return ret(0)
        self.once.add(x0); uc.reg_write(UC_ARM64_REG_X0,x1)
        uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x2); return
    return _orig_plt(self,uc,addr,size,ud)

e3.Emu.plt=patched_plt

if __name__=="__main__":
    import struct as _s
    e=e3.Emu(); d,f=e.run_init(verbose=False)
    print("init_array: %d/%d ran-to-ret"%(d,d+f))
    uc=e.uc
    for path in sys.argv[1:] or ["../cap.noindex/gt_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d"]:
        data=open(path,"rb").read()
        scratch=base+0x30000000; uc.mem_write(scratch,data)
        desc=scratch+0x100000; uc.mem_write(desc,_s.pack("<IiQ",0,len(data),scratch))
        out=scratch+0x180000; uc.mem_write(out,b"\x00"*32)
        cnt=int(os.environ.get("CNT","20000000"))
        err=e.call(e3.WORKER,(out,desc,1),count=cnt)
        pc=uc.reg_read(UC_ARM64_REG_PC)-base
        plain=e3.read_cxx_string(uc,out)
        pr=sum(1 for b in plain if 32<=b<127)
        print("[%s] worker pc=0x%x err=%s plain=%dB pr=%d%% head=%r"%(
            os.path.basename(path),pc,err,len(plain),(pr*100//len(plain)) if plain else 0, plain[:80]))
        if hasattr(e,"unhandled") and e.unhandled: print("   unhandled:",dict(e.unhandled))
