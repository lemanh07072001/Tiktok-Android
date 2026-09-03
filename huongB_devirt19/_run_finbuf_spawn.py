import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_f_inbuf.js",encoding="utf-8").read())
enters={}; rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="f_enter": enters[(p["tid"],p["n"])]=p
    if p.get("t")=="f_ret":
        e=enters.get((p["tid"],p["n"]),{})
        row={"n":p["n"],"slot16":p.get("slot16"),"inbuf":e.get("inbuf"),"derefs":e.get("derefs")}
        rows.append(row)
        print("\n[F #%d] slot16=%s"%(p["n"],p.get("slot16")))
        print("  inbuf=",e.get("inbuf"))
        for dd in (e.get("derefs") or []): print("   q%d ptr=%s data=%s"%(dd.get("q"),dd.get("ptr"),dd.get("data")))
        sys.stdout.flush()
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<50 and len(rows)<8: time.sleep(0.5)
json.dump(rows,open("_finbuf_out.json","w"),indent=1)
print("\n[DONE] F-pairs=%d"%len(rows),flush=True)
