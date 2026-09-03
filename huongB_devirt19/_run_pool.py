import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True); sess=dev.attach(pid)
JS=open("_correlate_seq.js",encoding="utf-8").read()
sc=sess.create_script(JS); pool=set()
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="sm3":
        s=p["slot16"]
        import re
        # filter ascii FP
        b=bytes.fromhex(s); pr=sum(1 for x in b if 0x20<=x<=0x7e)/16
        if pr<=0.7 and s not in pool:
            pool.add(s); print("[POOL] %s (reg=%s)"%(s,p.get("reg")),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<50 and len(pool)<8: time.sleep(0.5)
json.dump(sorted(pool),open("_pool_fresh.json","w"),indent=1)
print("[DONE] fresh pool size=%d"%len(pool),flush=True)
