import frida,sys,time,json
pid=int(sys.argv[1]); dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_catch_nonzero.js").read())
pool=[]; t0=time.time()
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="nz":
        pool.append(p); print("[NONZERO @%ds] %s q=%s"%(int(time.time()-t0),p["slot16"],p["qhead"]),flush=True)
        json.dump(pool,open("_pool_fresh.json","w"),indent=1)
sc.on("message",on); sc.load()
print("[*] persistent 600s capture running...",flush=True)
while time.time()-t0<600 and len(pool)<4: time.sleep(1)
json.dump(pool,open("_pool_fresh.json","w"),indent=1)
print("[DONE] nonzero=%d"%len(pool),flush=True)
