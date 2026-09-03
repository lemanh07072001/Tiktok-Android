import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
pid=int(sys.argv[1])
ent={"mem":{},"regions":{}}; slots=[]
def norm_save():
    r=ent["regions"]
    out={"entry":{"base":ent.get("base"),"tid":ent.get("tid"),"regs":ent.get("regs"),
         "bcptr":ent.get("bcptr"),"nmem":len(ent["mem"]),"mem":ent["mem"],
         "regfile":r.get("regfile",{}).get("hex"),
         "stack":r.get("stack",{}).get("hex"),"stackBase":r.get("stack",{}).get("vaddr"),
         "bytecode":r.get("bytecode",{}).get("hex"),
         "soRW":None,"soRWbase":None,
         "soData":r.get("soData",{}).get("hex"),"soDataBase":r.get("soData",{}).get("vaddr"),
         "ctxptr":ent.get("ctxptr"),
         "bcFull":r.get("bcFull",{}).get("hex"),"bcFullBase":r.get("bcFull",{}).get("vaddr")},
         "slots":slots}
    json.dump(out,open("_singleshot.json","w"))
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="region": ent["regions"][p["name"]]={"vaddr":p["vaddr"],"hex":p["hex"]}
    elif t=="memchunk": ent["mem"].update(p["mem"])
    elif t=="entry":
        ent["base"]=p["base"]; ent["tid"]=p["tid"]; ent["regs"]=p["regs"]; ent["bcptr"]=p.get("bcptr")
        norm_save()
        print("[ENTRY+SAVED] tid=%s base=%s mem=%d regions=%s"%(p["tid"],p["base"],len(ent["mem"]),list(ent["regions"].keys())),flush=True)
    elif t=="slot":
        slots.append(p); norm_save()
        print("[SLOT] %s"%("ZERO" if p["slot16"]=="00"*16 else "NONZERO "+p["slot16"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(pid); sc=sess.create_script(open("_vm_singleshot.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] loaded",flush=True)
t0=time.time()
while time.time()-t0<18 and ent.get("base") is None: time.sleep(0.3)
if ent.get("base"): time.sleep(6)
try: sess.detach()
except: pass
norm_save()
tid=ent.get("tid")
exp=[s["slot16"] for s in slots if s.get("tid")==tid and s["slot16"]!="00"*16]
print("[DONE] base=%s mem=%d bcFull=%s slots=%d EXPECTED=%s"%(
    ent.get("base"),len(ent["mem"]),bool(ent.get("regions",{}).get("bcFull")),len(slots), exp[0] if exp else "zero"),flush=True)
