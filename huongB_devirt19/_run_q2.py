import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
OUT=os.environ.get("Q2_OUT","_singleshot_ce0516.json")
PROG=os.environ.get("MSPROG","0x191f40")   # program F that compute_slot16.py replays
JSFILE=os.environ.get("JS_FILE","_vm_singleshot2.js")   # hardened capture (onLeave BFS + direct slot16)
ent={"mem":{},"regions":{}}; slots=[]
def norm_save():
    r=ent["regions"]
    out={"entry":{"base":ent.get("base"),"tid":ent.get("tid"),"regs":ent.get("regs"),
         "bcptr":ent.get("bcptr"),"ctxptr":ent.get("ctxptr"),"expected_slot16":ent.get("expected_slot16"),"nmem":len(ent["mem"]),"mem":ent["mem"],
         "regfile":r.get("regfile",{}).get("hex"),
         "stack":r.get("stack",{}).get("hex"),"stackBase":r.get("stack",{}).get("vaddr"),
         "bytecode":r.get("bytecode",{}).get("hex"),
         "soRW":None,"soRWbase":None,
         "soData":r.get("soData",{}).get("hex"),"soDataBase":r.get("soData",{}).get("vaddr"),
         "bcFull":r.get("bcFull",{}).get("hex"),"bcFullBase":r.get("bcFull",{}).get("vaddr"),
         "outrf":ent.get("outrf"),"outrf_x24":ent.get("outrf_x24"),
         "callout":ent.get("callout"),
         "directslot":ent.get("directslot"),"directdptr":ent.get("directdptr"),
         "callouts_a":ent.get("callouts_a"),"callouts_b":ent.get("callouts_b")},
         "slots":slots}
    json.dump(out,open(OUT,"w"))
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="maps":
        open("_maps.txt","w",encoding="utf-8").write(p.get("maps") or ""); print("[*] maps saved",flush=True)
    elif t=="region": ent["regions"][p["name"]]={"vaddr":p["vaddr"],"hex":p["hex"]}
    elif t=="memchunk": ent["mem"].update(p["mem"])
    elif t=="callout":
        ent.setdefault("callout",{})[p["site"]]=p.get("ret"); ent["mem"].update(p.get("mem") or {}); norm_save()
        print("[CALLOUT] site=%s ret=%s +%d pages"%(p["site"],p.get("ret"),len(p.get("mem") or {})),flush=True)
    elif t=="entry":
        ent["base"]=p["base"]; ent["tid"]=p["tid"]; ent["regs"]=p["regs"]; ent["bcptr"]=p.get("bcptr"); ent["ctxptr"]=p.get("ctxptr")
        norm_save()
        print("[ENTRY+SAVED] tid=%s base=%s mem=%d regions=%s"%(p["tid"],p["base"],len(ent["mem"]),list(ent["regions"].keys())),flush=True)
    elif t=="fctxptr":
        ent["ctxptr"]=p.get("val"); norm_save()
        print("[FCTXPTR] F's own context ptr = %s"%p.get("val"),flush=True)
    elif t=="directslot":
        ds=p.get("slot16"); ent["directslot"]=ds; ent["directdptr"]=p.get("dptr")
        ent["callouts_a"]=p.get("callouts_a"); ent["callouts_b"]=p.get("callouts_b")
        # direct binary output is the AUTHORITATIVE oracle (bypasses SM3 text-tail false positives)
        if ds and ds!="00"*16:
            ent["expected_slot16"]=ds
        norm_save()
        print("[DIRECTSLOT] slot16=%s dptr=%s callouts a=%s b=%s"%(
            ds,p.get("dptr"),p.get("callouts_a"),p.get("callouts_b")),flush=True)
    elif t=="outrf":
        ent["outrf"]=p.get("hex"); ent["outrf_x24"]=p.get("x24"); norm_save()
        print("[OUTRF] output regfile captured @ %s"%p.get("x24"),flush=True)
    elif t=="slot":
        slots.append(p)
        if ent.get("tid") and p.get("tid")==ent.get("tid") and p["slot16"]!="00"*16 and not ent.get("expected_slot16"):
            ent["expected_slot16"]=p["slot16"]; print("[EXPECTED] slot16 for captured F tid = %s"%p["slot16"],flush=True)
        norm_save()
        print("[SLOT] %s"%("ZERO" if p["slot16"]=="00"*16 else "NONZERO "+p["slot16"]),flush=True)

src="var MSPROG=%r;\n"%PROG + open(JSFILE,encoding="utf-8").read()
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,"prog=",PROG,"out=",OUT,flush=True)
sess=dev.attach(pid); sc=sess.create_script(src)
sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] resumed",flush=True)
WAIT=int(os.environ.get("Q2_WAIT","120"))
t0=time.time()
while time.time()-t0<WAIT and ent.get("base") is None: time.sleep(0.3)
t1=time.time()
while time.time()-t1<25 and (not ent.get('ctxptr') or not ent.get('expected_slot16')): time.sleep(0.3)
try: sess.detach()
except: pass
norm_save()
print("[DONE] base=%s mem=%d bcFull=%s slots=%d expected=%s"%(
    ent.get("base"),len(ent["mem"]),bool(ent.get("regions",{}).get("bcFull")),len(slots),ent.get("expected_slot16")),flush=True)
