#!/usr/bin/env python3
# _mss_load.py — drive the mssdk_setting store accessor/loader end-to-end using the
# logger-bypass + VFS infrastructure, then SCAN emulator memory for decrypted plaintext.
import sys, os, struct, importlib.util, re
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
spec=importlib.util.spec_from_file_location("g2","_mss_getter2.py")
sys.argv=["x"]; g2=importlib.util.module_from_spec(spec); spec.loader.exec_module(g2)
base=g2.base
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X8,UC_ARM64_REG_SP,
    UC_ARM64_REG_LR,UC_ARM64_REG_PC)

ENTRY=int(os.environ.get("ENTRY","0x6bb84"),16)

def scan_mem(uc, e):
    """Scan mapped heap/scratch for printable ASCII runs, JSON, zlib magic."""
    import zlib
    findings={"ascii":[],"zlib":[],"json":[]}
    regions=[(e.heap, e.hp+0x1000), (base+0x30000000, base+0x30400000)]
    for lo,hi in regions:
        try: blob=bytes(uc.mem_read(lo, min(hi-lo, 0x400000)))
        except Exception: continue
        # printable runs >=8
        for m in re.finditer(rb'[\x20-\x7e]{8,}', blob):
            s=m.group()
            if any(c in s for c in (b'{',b'"',b':',b'_')) and len(s)>=10:
                findings["ascii"].append(s[:200])
        # zlib
        for mg in (b'\x78\x01',b'\x78\x9c',b'\x78\xda'):
            i=0
            while True:
                j=blob.find(mg,i)
                if j<0: break
                i=j+1
                try:
                    d=zlib.decompressobj().decompress(blob[j:])
                    if len(d)>8 and sum(1 for c in d[:64] if 32<=c<127)>40:
                        findings["zlib"].append((j-lo, d[:200]))
                except Exception: pass
    # dedup ascii
    seen=set(); uniq=[]
    for s in findings["ascii"]:
        if s not in seen: seen.add(s); uniq.append(s)
    findings["ascii"]=uniq
    return findings

if __name__=="__main__":
    e=g2.Emu2(); d,f=e.run_init(verbose=False)
    print("init_array: %d/%d"%(d,d+f))
    uc=e.uc
    mss=open("../cap.noindex/gt_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d","rb").read()
    e.filedata=mss; e.opens=[]; e.fds={}; e.nextfd=3
    # x0 = scratch context/out object (512B), x8 = sret if needed
    ctx=base+0x30380000; uc.mem_write(ctx, b"\x00"*0x400)
    out=base+0x30390000; uc.mem_write(out, b"\x00"*0x400)
    uc.reg_write(UC_ARM64_REG_SP, e.sp0)
    uc.reg_write(UC_ARM64_REG_X0, ctx)
    uc.reg_write(UC_ARM64_REG_X8, out)
    uc.reg_write(UC_ARM64_REG_LR, e.RET)
    cnt=int(os.environ.get("CNT","200000000"))
    from unicorn import UcError
    try: uc.emu_start(base+ENTRY, e.RET, count=cnt); err=None
    except UcError as ex: err=str(ex)
    pc=uc.reg_read(UC_ARM64_REG_PC)-base
    print("entry=%#x pc=%#x err=%s opens=%s syscalls=%s null-blr=%d"%(
        ENTRY,pc,err,e.opens,{hex(k):v for k,v in e.syscalls.items()},len(e.skipped) if hasattr(e,'skipped') else -1))
    fnd=scan_mem(uc,e)
    print("\n=== MEMORY SCAN ===")
    print("zlib hits:",len(fnd["zlib"]))
    for off,d in fnd["zlib"][:10]: print("  zlib:",d)
    print("ascii/json-ish runs:",len(fnd["ascii"]))
    for s in fnd["ascii"][:60]: print("  ",s)
