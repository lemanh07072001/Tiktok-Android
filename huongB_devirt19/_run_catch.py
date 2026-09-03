import frida,sys,time,json
pid=int(sys.argv[1]); dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_catch_nonzero.js").read())
pool=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="nz":
        pool.append(p); print("[NONZERO] %s  q=%s mlen=%d"%(p["slot16"],p["qhead"],p["mlen"]),flush=True)
sc.on("message",on); sc.load()
t0=time.time()
while time.time()-t0<180 and len(pool)<6: time.sleep(0.5)
json.dump(pool,open("_pool_fresh.json","w"),indent=1)
print("[DONE] nonzero=%d"%len(pool),flush=True)
