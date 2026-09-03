#!/usr/bin/env python3
# _mss_reader.py — emulate the store-file READER 0xb0d10(x0=ctx, x1=keyname[, x8=out])
# which reads+decrypts a single store file (via 0x12e79c I/O). Validate on sdi_v2/.msp_092
# (known RC4 plaintext) then apply to mssdk_setting/.mss. VFS serves the file bytes.
import sys, os, struct, importlib.util, re
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
spec=importlib.util.spec_from_file_location("g2","_mss_getter2.py")
sys.argv=["x"]; g2=importlib.util.module_from_spec(spec); spec.loader.exec_module(g2)
base=g2.base
from unicorn import UcError
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X8,
    UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC)

READER=0xb0d10
def mkstr(e,uc,data):
    p=e.alloc(len(data)+1); uc.mem_write(p,data+b"\x00")
    s=e.alloc(0x18); uc.mem_write(s,struct.pack("<IIQ",len(data),len(data),p)); return s
def rdstr(uc,s):
    try:
        ln=struct.unpack_from("<I",bytes(uc.mem_read(s+4,4)),0)[0]
        dp=struct.unpack_from("<Q",bytes(uc.mem_read(s+8,8)),0)[0]
        return bytes(uc.mem_read(dp,ln)) if dp and 0<ln<(1<<20) else b""
    except UcError: return b""

def scan(uc,e):
    hits=set()
    for lo,hi in [(e.heap,e.hp+0x100),(base+0x30000000,base+0x30400000),(base+0x1f4000,base+0x1f6000)]:
        try: blob=bytes(uc.mem_read(lo,min(hi-lo,0x400000)))
        except UcError: continue
        for m in re.finditer(rb'[\x20-\x7e]{6,}', blob):
            s=m.group()
            if any(k in s for k in (b'kiid',b'dyn_',b'rtk2',b'rdk2',b'fltk',b'{',b'"',b'-0-1-',b'_ms',b'1233',b'3019')):
                hits.add(s[:120])
    return sorted(hits)

def run(keyname, filepath, x8out=True):
    e=g2.Emu2(); e.run_init(verbose=False); uc=e.uc
    e.filedata=open(filepath,"rb").read(); e.opens=[]; e.fds={}; e.nextfd=3
    ctx=base+0x30380000; uc.mem_write(ctx,b"\x00"*0x800)
    K=mkstr(e,uc,keyname); O=e.alloc(0x18); uc.mem_write(O,b"\x00"*0x18)
    uc.reg_write(UC_ARM64_REG_SP,e.sp0)
    uc.reg_write(UC_ARM64_REG_X0,ctx); uc.reg_write(UC_ARM64_REG_X1,K)
    if x8out: uc.reg_write(UC_ARM64_REG_X8,O)
    uc.reg_write(UC_ARM64_REG_LR,e.RET)
    try: uc.emu_start(base+READER,e.RET,count=int(os.environ.get("CNT","300000000"))); err=None
    except UcError as ex: err=str(ex)
    pc=uc.reg_read(UC_ARM64_REG_PC)-base
    out=rdstr(uc,O)
    print("[key=%s file=%s] pc=%#x err=%s opens=%s syscalls=%s out=%dB %r"%(
        keyname.decode(),os.path.basename(filepath)[:20],pc,err,e.opens,
        {hex(k):v for k,v in e.syscalls.items()},len(out),out[:80]))
    h=scan(uc,e)
    if h:
        print("   plaintext-ish (%d):"%len(h))
        for s in h[:40]: print("     ",s)

if __name__=="__main__":
    GT="../cap.noindex/gt_live/"
    print("=== VALIDATE on sdi_v2 (.msp_092, known RC4 plaintext) ===")
    run(b"sdi_v2", GT+".msp_092fde7a53a0274594af0984c7830fc0c13dc8bd")
    print("\n=== TARGET mssdk_setting (.mss) ===")
    run(b"mssdk_setting", GT+".mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d")
