import os,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; msgs=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; msgs.append(p)
    if p.get("t")=="info": print("[*]",p["msg"],flush=True)
    elif p.get("t")=="ok": print("[OK]",p["msg"],flush=True)
    elif p.get("t")=="err": print("[err]",p["msg"],flush=True)
    elif p.get("t")=="cnt": print("[CNT] store-callouts fired:",p["rc"],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_cm_iso.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<80 and not any(m.get("t") in ("cnt",) for m in msgs): time.sleep(0.4)
try: sess.detach()
except: pass
print("[DONE]",flush=True)
