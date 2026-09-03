#!/usr/bin/env python3
# Enrich _singleshot.json entry mem via passive /proc/mem (_dumpmem.sh bulk). Maps-based (robust).
import json, subprocess, struct, sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
D="ce05160592d7b31902"; pid=int(sys.argv[1])
d=json.load(open("_singleshot.json")); e=d["entry"]; base=int(e["base"],16)
HB="E:/Tiktok-Android/huongB_devirt19"

def adb(args, t=120):
    return subprocess.run(["adb","-s",D]+args, capture_output=True, timeout=t)

# readable page set from /proc/pid/maps
maps=adb(["shell","su -c 'cat /proc/%d/maps'"%pid],30).stdout.decode("utf-8","ignore")
readable=[]; exec_anon=[]
for ln in maps.splitlines():
    p=ln.split()
    if len(p)>=2 and "-" in p[0] and p[1][0]=="r":
        a,b=p[0].split("-"); ai,bi=int(a,16),int(b,16); readable.append((ai,bi))
        # executable anon regions (JIT closure trampolines the VM calls) — rwx/r-x, no file backing
        nm=p[5] if len(p)>=6 else ""
        if p[1][2]=="x" and (nm=="" or nm.startswith("[anon")) and (bi-ai)<=0x400000:
            exec_anon.append((ai,bi))
def is_read(va):
    return any(s<=va<e2 for s,e2 in readable)
def is_ptr(v): return 0x10000000 < v < 0x8000000000
def ptrs_of(hexstr):
    b=bytes.fromhex(hexstr)
    return [struct.unpack("<Q",b[o:o+8])[0] for o in range(0,len(b)-8,8) if is_ptr(struct.unpack("<Q",b[o:o+8])[0])]
def group(pages):
    pages=sorted(set(p&~0xfff for p in pages if is_read(p))); R=[]; i=0
    while i<len(pages):
        s=pages[i]; e2=s+0x1000
        while i+1<len(pages) and pages[i+1]<=e2+0x3000: i+=1; e2=pages[i]+0x1000
        R.append((s,e2)); i+=1
    return R
def dump(regions):
    if not regions: return {}
    open(HB+"/_targets_run.txt","w").write("\n".join("%x %x %d p"%(s,e2,e2-s) for s,e2 in regions))
    adb(["push",HB+"/_targets_run.txt","/data/local/tmp/_targets.txt"],30)
    r=adb(["shell","su -c 'sh /data/local/tmp/_dumpmem.sh %d'"%pid],200)
    adb(["pull","/data/local/tmp/_memdump.bin",HB+"/_memdump_run.bin"],90)
    adb(["pull","/data/local/tmp/_manifest.txt",HB+"/_manifest_run.txt"],30)
    blob=open(HB+"/_memdump_run.bin","rb").read(); out={}
    for ln in open(HB+"/_manifest_run.txt"):
        q=ln.split()
        if len(q)>=3:
            va=int(q[0],16); off=int(q[1]); rl=int(q[2])
            for i in range(0,rl,0x1000):
                pg=blob[off+i:off+i+0x1000]
                if len(pg)==0x1000 and any(pg): out[va+i]=pg
    return out

seen=set(int(k,16) for k in e["mem"].keys())
# level 0: whole .so (readable part) + handler-table + regfile/reg pointer pages
regions=[]
# .so: from base to base+0x1f4000 (grouped by readable)
so_pages=[base+o for o in range(0,0x200000,0x1000) if is_read(base+o)]
regions+=group(so_pages)
regions+=group([base+o for o in range(0x6a0000,0x6d0000,0x1000)])
ptr_pages=set()
for nm in ("regfile","stack"):
    if e.get(nm): ptr_pages|=set(p&~0xfff for p in ptrs_of(e[nm]))
for rv in (e.get("regs") or {}).values():
    try:
        v=int(rv,16)
        if is_ptr(v): ptr_pages.add(v&~0xfff)
    except: pass
regions+=group(ptr_pages)
regions+=exec_anon   # JIT closure trampoline regions (executable heap)
got=dump(regions)
for va,pg in got.items(): e["mem"].setdefault(hex(va),pg.hex()); seen.add(va)
print("[*] L1: %d pages"%len(e["mem"]),flush=True); json.dump(d,open("_singleshot.json","w"))
# levels 2-3: follow pointers
frontier=got
for lvl in (2,3):
    p2=set()
    for pg in frontier.values():
        for x in ptrs_of(pg.hex()):
            if (x&~0xfff) not in seen: p2.add(x&~0xfff)
    got2=dump(group(list(p2)[:2000]))
    for va,pg in got2.items(): e["mem"].setdefault(hex(va),pg.hex()); seen.add(va)
    print("[*] L%d: total %d pages"%(lvl,len(e["mem"])),flush=True)
    frontier=got2
    if not got2: break
json.dump(d,open("_singleshot.json","w")); print("[DONE] mem=%d"%len(e["mem"]),flush=True)
