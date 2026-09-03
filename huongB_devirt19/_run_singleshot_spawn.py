import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
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
         "outrf":ent.get("outrf"),"outrf_x24":ent.get("outrf_x24")},
         "slots":slots}
    json.dump(out,open("_singleshot.json","w"))
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="maps":
        open("_maps.txt","w",encoding="utf-8").write(p.get("maps") or ""); print("[*] maps saved",flush=True)
    elif t=="region": ent["regions"][p["name"]]={"vaddr":p["vaddr"],"hex":p["hex"]}
    elif t=="memchunk": ent["mem"].update(p["mem"])
    elif t=="entry":
        ent["base"]=p["base"]; ent["tid"]=p["tid"]; ent["regs"]=p["regs"]; ent["bcptr"]=p.get("bcptr"); ent["ctxptr"]=p.get("ctxptr")
        norm_save()
        print("[ENTRY+SAVED] tid=%s base=%s mem=%d regions=%s"%(p["tid"],p["base"],len(ent["mem"]),list(ent["regions"].keys())),flush=True)
    elif t=="fctxptr":
        ent["ctxptr"]=p.get("val"); norm_save()
        print("[FCTXPTR] F's own context ptr = %s"%p.get("val"),flush=True)
    elif t=="outrf":
        ent["outrf"]=p.get("hex"); ent["outrf_x24"]=p.get("x24"); norm_save()
        print("[OUTRF] output regfile captured @ %s"%p.get("x24"),flush=True)
    elif t=="slot":
        slots.append(p);
        # expected slot16 = first nonzero slot on the captured F's tid, after entry
        if ent.get("tid") and p.get("tid")==ent.get("tid") and p["slot16"]!="00"*16 and not ent.get("expected_slot16"):
            ent["expected_slot16"]=p["slot16"]; print("[EXPECTED] slot16 for captured F tid = %s"%p["slot16"],flush=True)
        norm_save()
        print("[SLOT] %s"%("ZERO" if p["slot16"]=="00"*16 else "NONZERO "+p["slot16"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sess=dev.attach(pid); sc=sess.create_script(open("_vm_singleshot.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] resumed",flush=True)
t0=time.time()
while time.time()-t0<90 and ent.get("base") is None: time.sleep(0.3)
t1=time.time()
while time.time()-t1<20 and (not ent.get('ctxptr') or not ent.get('expected_slot16')): time.sleep(0.3)
try: sess.detach()
except: pass
norm_save()
print("[DONE] base=%s mem=%d bcFull=%s slots=%d"%(
    ent.get("base"),len(ent["mem"]),bool(ent.get("regions",{}).get("bcFull")),len(slots)),flush=True)
