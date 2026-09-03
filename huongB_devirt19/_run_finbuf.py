import frida,sys,time,json
pid=int(sys.argv[1]); dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_f_inbuf.js",encoding="utf-8").read())
rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="f":
        rows.append(p)
        print("\n[F #%d] slot16=%s"%(p["n"],p["slot16"]))
        print("  inbuf=",p["inbuf"])
        for dd in p["derefs"]:
            print("   q%d ptr=%s data=%s"%(dd.get("q"),dd.get("ptr"),dd.get("data")))
        sys.stdout.flush()
sc.on("message",on); sc.load()
t0=time.time()
while time.time()-t0<50 and len(rows)<6: time.sleep(0.5)
json.dump(rows,open("_finbuf_out.json","w"),indent=1)
print("\n[DONE] F-calls=%d"%len(rows))
