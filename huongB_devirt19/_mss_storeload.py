#!/usr/bin/env python3
# _mss_storeload.py — VALIDATE the store-load emulation on the DEVICE-SECRET store
# (0x1185d0 getter → 0x117e14 loader → 0x52924 iterate → callback 0x1188e0 populate).
# We serve .msp_589 via VFS and dump the populated store singleton @0x1fb910; if known
# device-secret fields (kiid/dyn_seed) appear, the DB-load emulation WORKS → apply to mssdk_setting.
import sys, os, struct, importlib.util, re
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
spec=importlib.util.spec_from_file_location("g2","_mss_getter2.py")
sys.argv=["x"]; g2=importlib.util.module_from_spec(spec); spec.loader.exec_module(g2)
base=g2.base
from unicorn import UcError
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC)

GETTER=int(os.environ.get("GETTER","0x1185d0"),16)
FILE=os.environ.get("FILE","../cap.noindex/gt_live/.msp_589c22335a381f122d129225f5c0ba3056ed5811")

def scan(uc,e,label):
    import zlib
    hits=set()
    regions=[(e.heap,e.hp+0x100),(base+0x1fb000,base+0x1fc000),(base+0x30000000,base+0x30400000)]
    for lo,hi in regions:
        try: blob=bytes(uc.mem_read(lo,min(hi-lo,0x400000)))
        except UcError: continue
        for m in re.finditer(rb'[\x20-\x7e]{6,}', blob):
            s=m.group()
            if any(k in s for k in (b'kiid',b'dyn_',b'rtk2',b'rdk2',b'fltk',b'bootsoft',b'{',b'"',b'-0-1-',b'_ms')):
                hits.add(s[:120])
    print("=== [%s] plaintext-ish strings (%d) ==="%(label,len(hits)))
    for s in sorted(hits)[:60]: print("  ",s)

if __name__=="__main__":
    e=g2.Emu2(); d,f=e.run_init(verbose=False)
    print("init_array %d/%d ; getter=%#x file=%s"%(d,d+f,GETTER,os.path.basename(FILE)))
    uc=e.uc
    e.filedata=open(FILE,"rb").read(); e.opens=[]; e.fds={}; e.nextfd=3
    uc.reg_write(UC_ARM64_REG_SP,e.sp0); uc.reg_write(UC_ARM64_REG_X0,0)
    uc.reg_write(UC_ARM64_REG_LR,e.RET)
    cnt=int(os.environ.get("CNT","300000000"))
    try: uc.emu_start(base+GETTER,e.RET,count=cnt); err=None
    except UcError as ex: err=str(ex)
    pc=uc.reg_read(UC_ARM64_REG_PC)-base
    ret=uc.reg_read(UC_ARM64_REG_X0)
    print("pc=%#x err=%s ret=%#x opens=%s syscalls=%s nullblr=%d"%(
        pc,err,ret,e.opens,{hex(k):v for k,v in e.syscalls.items()},len(getattr(e,'skipped',[]))))
    scan(uc,e,os.path.basename(FILE))

# extra: print skip sites when run with SKIPS=1
if os.environ.get("SKIPS"):
    pass
