#!/usr/bin/env python3
# Unicorn replay of native slot16 producer 0x879d8 (leaf) → compute slot16 offline.
import json,struct,sys
from unicorn import *
from unicorn.arm64_const import *
o=json.load(open("_slot16cap_out.json"))
meta=o["meta"]; closure=o["closure"]; sochunks=o["so_chunks"]
base=int(meta["base"],16); msize=meta["msize"]
FN=base+0x879d8; RET=base+0x87cf4
regs=meta["regs"]
def h2b(h): return bytes.fromhex(h) if h else b""
uc=Uc(UC_ARCH_ARM64, UC_MODE_ARM)
def mapfill(addr,size):
    a=addr&~0xfff; end=(addr+size+0xfff)&~0xfff
    try: uc.mem_map(a,end-a)
    except UcError: pass
# map .so: runtime dump for data/got/bss, FILE for .text (avoid our own hook trampoline)
mapfill(base, msize)
fb=open("bin/libmetasec_ov.so","rb").read()
img=bytearray(fb[:msize].ljust(msize,b"\0"))   # start from FILE image (original code+rodata)
for off,hx in sochunks:                          # overlay runtime data (relocated/init) where dumped
    if hx and off>=0x1e0000:                      # data/got/bss region only
        b=h2b(hx); img[off:off+len(b)]=b
# ensure function code = FILE (un-hooked)
img[0x879d8:0x87cf4]=fb[0x879d8:0x87cf4]
uc.mem_write(base, bytes(img))
# map closure windows (ctx + pointer closure)
mapped=set()
for w in closure:
    a=int(w["a"],16)
    if a in mapped: continue
    mapped.add(a); mapfill(a,0x1000)
    try: uc.mem_write(a, h2b(w["b64"]))
    except UcError: pass
# stack
sp=int(regs["sp"],16); mapfill(sp-0x8000, 0x10000)
stk=meta["stack"]
if stk and stk.get("b64"): 
    try: uc.mem_write(int(stk["a"],16), h2b(stk["b64"]))
    except: pass
# registers
RMAP={'x0':UC_ARM64_REG_X0,'x1':UC_ARM64_REG_X1,'x2':UC_ARM64_REG_X2,'x3':UC_ARM64_REG_X3,'x4':UC_ARM64_REG_X4,'x5':UC_ARM64_REG_X5,'x6':UC_ARM64_REG_X6,'x7':UC_ARM64_REG_X7,'x8':UC_ARM64_REG_X8,'x9':UC_ARM64_REG_X9,'x10':UC_ARM64_REG_X10,'x11':UC_ARM64_REG_X11,'x12':UC_ARM64_REG_X12,'x13':UC_ARM64_REG_X13,'x14':UC_ARM64_REG_X14,'x15':UC_ARM64_REG_X15,'x16':UC_ARM64_REG_X16,'x17':UC_ARM64_REG_X17,'x18':UC_ARM64_REG_X18,'x19':UC_ARM64_REG_X19,'x20':UC_ARM64_REG_X20,'x21':UC_ARM64_REG_X21,'x22':UC_ARM64_REG_X22,'x23':UC_ARM64_REG_X23,'x24':UC_ARM64_REG_X24,'x25':UC_ARM64_REG_X25,'x26':UC_ARM64_REG_X26,'x27':UC_ARM64_REG_X27,'x28':UC_ARM64_REG_X28,'fp':UC_ARM64_REG_FP,'lr':UC_ARM64_REG_LR,'sp':UC_ARM64_REG_SP}
for r,rc in RMAP.items():
    if r in regs: uc.reg_write(rc,int(regs[r],16))

# TPIDR_EL0 (TLS) — map a page + set canary so mrs/canary reads are consistent
TLS=0x70000000; mapfill(TLS,0x1000)
try: uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
except Exception as e: print("no TPIDR reg:",e)
uc.mem_write(TLS+0x28, (0x1122334455667788).to_bytes(8,'little'))  # canary
# resolve GOT 0x1ef000+0xfb0 pointer from .so dump, check mapped
try:
    got=uc.mem_read(base+0x1ef000+0xfb0,8); gp=int.from_bytes(got,'little')
    print("GOT[0x1ef000+0xfb0] -> 0x%x (in .so: %s)"%(gp, base<=gp<base+msize))
    mapfill(gp,0x1000)
except Exception as e: print("got resolve err",e)
# trace br/last insns
TR=[]
def on_code(uc,addr,size,ud):
    if len(TR)<4000: TR.append(addr)
uc.hook_add(UC_HOOK_CODE, on_code)

# lazy-map unmapped reads
def on_unmapped(uc,access,addr,size,value,ud):
    mapfill(addr,max(size,0x1000)); return True
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)
# snapshot writable region before, to diff after
def snap_ctx():
    out={}
    for w in closure[:20]:
        a=int(w["a"],16)
        try: out[a]=uc.mem_read(a,0x1000)
        except: pass
    return out
before=snap_ctx()
print("running 0x879d8 (url=%s)..."%meta["url"])
try:
    uc.emu_start(FN, RET, count=2000000)
    print("  emu reached/stopped. pc=0x%x"%uc.reg_read(UC_ARM64_REG_PC))
except UcError as e:
    print("  UcError:",e,"pc=0x%x"%uc.reg_read(UC_ARM64_REG_PC))
    print("  trace tail (last 12):",["0x%x"%a for a in TR[-12:]])
    print("  in-func insns:",sum(1 for a in TR if base+0x879d8<=a<=base+0x87cf4),"/",len(TR))
# DUMP output region: x0(ctx), x3-buffer, stack, return — find the 16B slot16
def rd(a,n):
    try: return bytes(uc.mem_read(a,n))
    except: return b""
x0=uc.reg_read(UC_ARM64_REG_X0); x3=int(regs["x3"],16); x0ret=uc.reg_read(UC_ARM64_REG_X0)
print("  x0(after)=0x%x  ret=0x%x"%(x0, uc.reg_read(UC_ARM64_REG_X0)))
# dump around ctx x0, x3 target, and follow x3 pointers
print("  ctx x0 region:", rd(x0, 96).hex())
for label,a in [("x3",x3),("x0+0x88",int(regs["x0"],16)+0x88)]:
    print("  %s: %s"%(label, rd(a,64).hex()))
    try:
        p=int.from_bytes(rd(a,8),'little')
        if p: print("     ->deref: %s"%rd(p,48).hex())
    except: pass
# stack near sp
sp=uc.reg_read(UC_ARM64_REG_SP)
print("  stack@sp:", rd(sp,128).hex())
os_exit=0

# scan stack for 32-char ASCII hex string (= slot16 hex per note 55/56)
import re as _re
sp0=int(regs["sp"],16)
region=b""
for a in range(sp0-0x300, sp0+0x300, 0x40):
    region+=rd(a,0x40) or b''
txt=region.decode("latin1")
for m in _re.finditer(r'[0-9a-f]{32,64}', txt):
    print("  HEX-STRING found (slot16 candidate?):", m.group(0)[:64])
# also read the specific sp+0x190 offset (relative to entry sp)
for off in [0x190,0x150,0x170,0x1a0,0x1b0]:
    v=rd(sp0-0x250+off, 32)
    if v and len(v)==64: 
        aa=bytes.fromhex(v) if isinstance(v,str) else bytes(v); asci=''.join(chr(x) if 32<=x<=126 else '.' for x in aa)
        if aa!=b"\0"*32: print("  frame+0x%x: %s (%r)"%(off,v,asci[:32]))
