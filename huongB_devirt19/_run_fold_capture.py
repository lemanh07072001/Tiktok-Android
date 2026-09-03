import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 25
CAP=int(sys.argv[2]) if len(sys.argv)>2 else 200
calls=[]; orchs=[]; info=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": info.append(p["msg"]); print("[*]",p["msg"],flush=True)
    elif t=="orch": orchs.append(p["seq"])
    elif t=="call":
        calls.append(p)
        if len(calls)%20==0: print("[*] calls=%d orch=%d"%(len(calls),len(orchs)),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sess=dev.attach(pid)
src="const FOLD_CAP=%d;\n"%CAP + open("_fold_capture.js",encoding="utf-8").read()
sc=sess.create_script(src); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] resumed, collecting %ds"%SECS,flush=True)
t0=time.time()
while time.time()-t0<SECS and len(calls)<CAP: time.sleep(0.3)
try: sess.detach()
except: pass
json.dump({"calls":calls,"orch_total":(orchs[-1] if orchs else 0),"ncalls":len(calls)},open("_fold_out.json","w"))
print("[DONE] calls=%d orch_total=%d saved _fold_out.json"%(len(calls),(orchs[-1] if orchs else 0)),flush=True)
