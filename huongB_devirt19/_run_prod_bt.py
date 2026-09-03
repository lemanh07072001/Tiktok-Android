import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; got=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="prod":
        got.append(p)
        print("\n[PROD] slot16=%s src=%s"%(p["slot16"],p["src"]),flush=True)
        print("  srcRegion:",p["srcRegion"],flush=True)
        print("  around(src-0x40..+0x80):",p["around"],flush=True)
        print("  backtrace(ACCURATE):",flush=True)
        for b in p["bt"][:16]: print("     ",b,flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_slot16_prod_bt.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<80 and len(got)<3: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(got,open("_prod_bt_out.json","w"))
print("\n[DONE] %d captured"%len(got),flush=True)
