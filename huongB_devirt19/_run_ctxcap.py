import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
out={"entry":None,"mem":{},"ctx":None,"regfile":None,"stack":None,"stackBase":None,"regfileBase":None}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="ctx": out["ctx"]=p; print("[CTX] ctxptr=%s npg=%d"%(p["ctxptr"],p["npg"]),flush=True)
    elif t=="region":
        if p["name"]=="regfile": out["regfile"]=p["hex"]; out["regfileBase"]=p["vaddr"]
        elif p["name"]=="stack": out["stack"]=p["hex"]; out["stackBase"]=p["vaddr"]
    elif t=="memchunk": out["mem"].update(p["mem"])
    elif t=="entry": out["entry"]=p; print("[ENTRY] nmem=%d ctxDone=%s"%(p["nmem"],p.get("ctxDone")),flush=True)
    elif t=="done": print("[DONE-script]",flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sess=dev.attach(pid); sc=sess.create_script(open("_vm_ctxcap.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<75 and out["entry"] is None: time.sleep(0.3)
time.sleep(3)
try: sess.detach()
except: pass
json.dump(out,open("_ctxcap.json","w"))
e=out.get("entry") or {}
print("[SAVED] nmem=%d ctxptr=%s regfile=%s"%(len(out["mem"]), (out.get("ctx") or {}).get("ctxptr"), "ok" if out.get("regfile") else "NULL"),flush=True)
