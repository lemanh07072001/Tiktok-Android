import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; res=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="follow": print("[FOLLOW] tid=%s"%p["tid"],flush=True)
    elif t=="err": print("[err]",p["msg"],flush=True)
    elif t=="result":
        res.append(p)
        print("\n[RESULT] slot16=%s ring=%d hits=%d"%(p["slot16"],p["ringlen"],p["nhits"]),flush=True)
        for h in p["hits"]: print("   HIT pc=%s tgt=%s val=%s"%(h["pc"],h["tgt"],h["val16"]),flush=True)
        print("   sample arena stores (last6):",flush=True)
        for h in p["sampleArena"]: print("      pc=%s tgt=%s val=%s"%(h["pc"],h["tgt"],h["val16"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_stalker_producer.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<90 and len(res)<3: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(res,open("_stalker_prod_out.json","w"))
print("\n[DONE] %d results"%len(res),flush=True)
