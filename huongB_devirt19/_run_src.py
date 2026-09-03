import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_slot16_source.js",encoding="utf-8").read())
rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="src":
        rows.append(p); print("[SRC] slot16=%s via=%s addr=%s region=%s"%(p["slot16"],p["via"],p["addr"],p["region"]),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<50 and len(rows)<8: time.sleep(0.5)
json.dump(rows,open("_src_out.json","w"),indent=1)
print("\n[DONE] sources=%d"%len(rows),flush=True)
