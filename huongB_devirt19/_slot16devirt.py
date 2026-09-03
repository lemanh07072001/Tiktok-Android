import json
from unicorn import *
from unicorn.arm64_const import *
o=json.load(open("_slot16full_out.json"))
meta=o["meta"]; closure=o["closure"]; sochunks=o["so_chunks"]
base=int(meta["base"],16); msize=meta["msize"]
FN=base+0x879d8
regs=meta["regs"]; want_hex=meta["slot16_hex"]; want_bytes=bytes.fromhex(want_hex)
want_ascii=want_hex.encode()
LR=int(regs["lr"],16)                 # ★ exit tự nhiên = return về caller
def h2b(h): return bytes.fromhex(h) if h else b""
uc=Uc(UC_ARCH_ARM64, UC_MODE_ARM)
def mapfill(addr,size):
    a=addr&~0xfff; end=(addr+size+0xfff)&~0xfff
    try: uc.mem_map(a,end-a)
    except UcError: pass
mapfill(base,msize)
fb=open("bin/libmetasec_ov.so","rb").read()
img=bytearray(fb[:msize].ljust(msize,b"\0"))
for off,hx in sochunks:
    if hx and off>=0x1e0000: b=h2b(hx); img[off:off+len(b)]=b
try:
    gap=json.load(open("_slot16_gappages.json"))
    for off,hx in gap.items():
        if hx: b=h2b(hx); off=int(off); img[off:off+len(b)]=b
    print("overlaid gap pages:", list(gap.keys()))
except Exception as e: print("no gap pages:",e)
uc.mem_write(base,bytes(img))
mapped=set()
for w in closure:
    a=int(w["a"],16)
    if a in mapped: continue
    mapped.add(a); mapfill(a,0x1000)
    try: uc.mem_write(a,h2b(w["b64"]))
    except: pass
sp=int(regs["sp"],16); mapfill(sp-0x20000,0x40000)
stk=meta["stack"]
if stk.get("b64"):
    try: uc.mem_write(int(stk["a"],16),h2b(stk["b64"]))
    except: pass
RMAP={('x%d'%i):getattr(__import__('unicorn.arm64_const',fromlist=['x']),'UC_ARM64_REG_X%d'%i) for i in range(29)}
RMAP['fp']=UC_ARM64_REG_FP; RMAP['lr']=UC_ARM64_REG_LR; RMAP['sp']=UC_ARM64_REG_SP
for r,rc in RMAP.items():
    if r in regs: uc.reg_write(rc,int(regs[r],16))
TLS=0x70000000; mapfill(TLS,0x1000); uc.reg_write(UC_ARM64_REG_TPIDR_EL0,TLS)
uc.mem_write(TLS+0x28,(0x1122334455667788).to_bytes(8,'little'))

# ---- tracing ----
icount=[0]; calls=[]; hexhits=[]
KNOWN={0x8913c:"map_lookup",0x89320:"consumer",0x891f4:"UNHEX",0x9fdac:"SM3drv",
       0x14fc68:"str_ctor",0x17915c:"strdec",0x1796e4:"strdec2"}
last_call=[None]
def on_code(uc,addr,size,ud):
    icount[0]+=1
    off=addr-base
    if off in KNOWN:
        calls.append((icount[0],off,KNOWN[off]))
        if len(calls)<=60: print("  [%d] enter 0x%x %s"%(icount[0],off,KNOWN[off]))
def on_write(uc,acc,addr,size,val,ud):
    try: b=val.to_bytes(size,'little')
    except: return
    # bắt khi ghi ra byte của slot16 (raw) hoặc ký tự hex chuỗi slot16
    if want_bytes[:4] in b or want_bytes[4:8] in b:
        pc=uc.reg_read(UC_ARM64_REG_PC)
        hexhits.append(("RAW",pc,addr,b.hex()))
        print("  ★RAW slot16 bytes WRITTEN pc=0x%x addr=0x%x val=%s"%(pc-base,addr,b.hex()))
def on_unmapped(uc,acc,addr,size,val,ud): mapfill(addr,max(size,0x1000)); return True
uc.hook_add(UC_HOOK_CODE,on_code)
uc.hook_add(UC_HOOK_MEM_WRITE,on_write)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

print("want slot16 = %s ; FN=0x879d8 → exit LR=0x%x"%(want_hex,LR-base if base<=LR<base+msize else LR))
try:
    uc.emu_start(FN,LR,count=8000000)
    print("emu EXIT pc=0x%x  icount=%d"%(uc.reg_read(UC_ARM64_REG_PC),icount[0]))
except UcError as e:
    print("UcError:",e,"pc=0x%x icount=%d"%(uc.reg_read(UC_ARM64_REG_PC)-base,icount[0]))
print("\ncalls seen:", [(c[1],c[2]) for c in calls][:40])
# search
found=[]
for r in uc.mem_regions():
    try: mem=bytes(uc.mem_read(r.begin,r.end-r.begin))
    except: continue
    i=mem.find(want_bytes)
    if i>=0: found.append("RAW @0x%x"%(r.begin+i))
    j=mem.find(want_ascii)
    if j>=0: found.append("ASCII @0x%x"%(r.begin+j))
print("\n=== SEARCH slot16 ===")
print("  ✅ FOUND:",found if found else "❌ not found")
