import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 90
out={"entry":None,"mem":{},"ctx":None,"regfile":None,"stack":None,"stackBase":None}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="ctx": out["ctx"]=p; print("[CTX] ctxptr=%s npg=%d"%(p["ctxptr"],p["npg"]),flush=True)
    elif t=="region":
        if p["name"]=="regfile": out["regfile"]=p["hex"]
        elif p["name"]=="stack": out["stack"]=p["hex"]; out["stackBase"]=p["vaddr"]
    elif t=="memchunk": out["mem"].update(p["mem"])
    elif t=="entry": out["entry"]=p; print("[ENTRY] nmem=%d ctxDone=%s"%(p["nmem"],p.get("ctxDone")),flush=True)
    elif t=="done": print("[DONE]",flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID)
sc=sess.create_script("const MSPROG='0x191f40';\n"+open("_vm_ctxcap.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] attached %d, %ds window"%(PID,SECS),flush=True)
t0=time.time()
while time.time()-t0<SECS and out["entry"] is None: time.sleep(0.4)
time.sleep(2)
json.dump(out,open("_ctxcap_F.json","w"))
print("[SAVED-JSON]",flush=True)
try: sess.detach()
except: pass
print("[SAVED] nmem=%d ctxptr=%s regfile=%s"%(len(out["mem"]),(out.get("ctx") or {}).get("ctxptr"),"ok" if out.get("regfile") else "NULL"),flush=True)
