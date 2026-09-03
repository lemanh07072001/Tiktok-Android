import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; hits=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="hit":
        hits.append(p)
        print("\n[HIT] slot16=%s carriers=%d ring=%d"%(p["slot16"],p["ncarriers"],p["ringlen"]),flush=True)
        for c in p["carriers"]:
            print("   #%d %s ra=%s off=%d len=%d src=%s dst=%s"%(c["i"],c["fn"],c["ra"],c["off"],c["len"],c["src"],c["dst"]),flush=True)
            print("       srcHead=%s"%c["srcHead"],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_slot16_provenance.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<80 and len(hits)<4: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(hits,open("_provenance_out.json","w"))
print("\n[DONE] %d hits saved"%len(hits),flush=True)
