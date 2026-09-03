import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 40
CAP=int(sys.argv[2]) if len(sys.argv)>2 else 12
nz=[]; info=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": info.append(p["msg"]); print("[*]",p["msg"],flush=True)
    elif t=="nz":
        nz.append(p); print("[NZ #%d] slot16=%s mlen=%d nprog=%d qhead=%s"%(len(nz),p["slot16"],p["mlen"],len(p["progseq"]),p["query"][:46]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sess=dev.attach(pid)
src="const FL_CAP=%d;const FL_WIN=100;\n"%CAP + open("_f_locate.js",encoding="utf-8").read()
sc=sess.create_script(src); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] resumed, collecting %ds"%SECS,flush=True)
t0=time.time()
while time.time()-t0<SECS and len(nz)<CAP: time.sleep(0.3)
try: sess.detach()
except: pass
json.dump({"nz":nz},open("_f_locate_out.json","w"))
print("[DONE] nz=%d saved _f_locate_out.json"%len(nz),flush=True)
