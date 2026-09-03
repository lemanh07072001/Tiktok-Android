import frida,sys,time,json
pid=int(sys.argv[1]); dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_correlate_seq.js",encoding="utf-8").read())
pool=set(); cnt=[0]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="sm3":
        cnt[0]+=1; s=p["slot16"]
        b=bytes.fromhex(s); pr=sum(1 for x in b if 0x20<=x<=0x7e)/16
        if pr<=0.7 and s not in pool: pool.add(s); print("[POOL] %s"%s,flush=True)
sc.on("message",on); sc.load()
t0=time.time()
while time.time()-t0<90 and len(pool)<8: time.sleep(0.5)
json.dump(sorted(pool),open("_pool_fresh.json","w"),indent=1)
print("[DONE] #19-detections=%d pool=%d"%(cnt[0],len(pool)),flush=True)
