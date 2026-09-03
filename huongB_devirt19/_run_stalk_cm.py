import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; res=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="follow": print("[FOLLOW] tid=%s"%p["tid"],flush=True)
    elif t=="err": print("[err]",p["msg"],flush=True)
    elif t=="mon": print("   [mon] poolN=%d ringN=%d learned=%d"%(p["poolN"],p["ringN"],p["learnedN"]),flush=True)
    elif t=="cap":
        res.append(p)
        print("\n[CAP] ringN=%d poolN=%d learned=%d"%(p["ringN"],p["poolN"],p["learnedN"]),flush=True)
        if p["hits"]:
            for h in p["hits"]: print("   *** HIT %s pc=%s tgt=%s val=%s"%(h["kind"],h["pc"],h["tgt"],h.get("val")),flush=True)
        else: print("   (no ring store matched a learned slot16)",flush=True)
        for r in p["sample"][:8]: print("     store pc=%s tgt=%s vlo=%s vhi=%s"%(r["pc"],r["tgt"],r["vlo"],r["vhi"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_stalk_cm.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<70: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(res,open("_stalk_cm_out.json","w"))
print("\n[DONE] captures=%d"%len(res),flush=True)
