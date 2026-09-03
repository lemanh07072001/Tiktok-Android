import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 60; CAP=int(sys.argv[3]) if len(sys.argv)>3 else 6
nz=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="nz":
        nz.append(p); print("[NZ #%d] slot16=%s"%(len(nz),p["slot16"]),flush=True)
        for f in p["bt"][:14]: print("     ",f,flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID)
src="const BT_CAP=%d;\n"%CAP+open("_f_native_bt.js",encoding="utf-8").read()
sc=sess.create_script(src); sc.on("message",on_msg); sc.load()
print("[*] attached %d %ds"%(PID,SECS),flush=True)
t0=time.time()
while time.time()-t0<SECS and len(nz)<CAP: time.sleep(0.3)
try: sess.detach()
except: pass
json.dump({"nz":nz},open("_native_bt_out.json","w")); print("[DONE] nz=%d"%len(nz),flush=True)
