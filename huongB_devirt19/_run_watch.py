import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_slot16_watch.js",encoding="utf-8").read())
rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="access":
        rows.append(p)
        print("[ACCESS] %s addr=%s FROM=%s (in_so=%s off=%s)"%(p["op"],p["addr"],p["from_res"],p["in_so"],p["from_off"]),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<40 and len(rows)<10: time.sleep(0.5)
json.dump(rows,open("_watch_out.json","w"),indent=1)
print("\n[DONE] accesses=%d"%len(rows),flush=True)
