import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_correlate_seq.js",encoding="utf-8").read())
pool=set(); cnt=[0]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="sm3":
        cnt[0]+=1; s=p["slot16"]; b=bytes.fromhex(s); pr=sum(1 for x in b if 0x20<=x<=0x7e)/16
        if pr<=0.7 and s not in pool: pool.add(s); print("[POOL] %s reg=%s"%(s,p.get("reg")),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<75 and len(pool)<6: time.sleep(0.5)
json.dump(sorted(pool),open("_pool_fresh.json","w"),indent=1)
print("[DONE] #19=%d pool=%d"%(cnt[0],len(pool)),flush=True)
