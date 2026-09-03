import frida,sys,time,json
pid=int(sys.argv[1]); dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_closure_trace.js",encoding="utf-8").read())
rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"]);return
    if p.get("t")=="closure":
        rows.append(p); print("[CLOSURE] slot=%s ptr=%s concat=0x%s expected=%s"%(p["slot16"],p["slotPtr"],p["concat"],p["concatIsExpected"]),flush=True)
sc.on("message",on); sc.load()
t0=time.time()
while time.time()-t0<40: time.sleep(0.5)
json.dump(rows,open("_closure_out.json","w"),indent=1)
print("[DONE] closures=%d ptr-stable=%s"%(len(rows), len(set(r["slotPtr"] for r in rows))<=2 if rows else "n/a"))
