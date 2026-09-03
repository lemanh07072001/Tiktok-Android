import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 100
out={"entry":None,"mem":{},"regfile":None,"stack":None,"stackBase":None,"trace":[],"ctx":None}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="ctx": out["ctx"]=p; print("[CTX] ctxptr=%s npg=%d ntrace=%d slot16=%s"%(p["ctxptr"],p["npg"],p["ntrace"],p.get("slot16")),flush=True)
    elif t=="region":
        if p["name"]=="regfile": out["regfile"]=p["hex"]
        elif p["name"]=="stack": out["stack"]=p["hex"]; out["stackBase"]=p["vaddr"]
    elif t=="memchunk": out["mem"].update(p["mem"])
    elif t=="trace": 
        while len(out["trace"])<p["from"]: out["trace"].append(None)
        out["trace"][p["from"]:p["from"]+len(p["rows"])]=p["rows"]
    elif t=="entry": out["entry"]=p; print("[ENTRY] nmem=%d ntrace=%d slot16=%s"%(p["nmem"],p.get("ntrace"),p.get("slot16")),flush=True)
    elif t=="done": print("[DONE]",flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID)
sc=sess.create_script("const MSPROG='0x191f40';\n"+open("_vm_ctxtrace.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] attached %d %ds"%(PID,SECS),flush=True)
t0=time.time()
while time.time()-t0<SECS and out["entry"] is None: time.sleep(0.4)
time.sleep(2)
json.dump(out,open("_ctxtrace.json","w")); print("[SAVED-JSON] mem=%d trace=%d slot16=%s"%(len(out["mem"]),len(out["trace"]),(out.get("ctx") or {}).get("slot16")),flush=True)
try: sess.detach()
except: pass
