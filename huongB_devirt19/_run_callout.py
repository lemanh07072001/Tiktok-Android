import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_native_callout.js",encoding="utf-8").read())
rows=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="callout":
        rows.append(p)
        print("\n[CALLOUT %s hit#%d] method=%s (%s+%s)"%(p["tag"],p["hit"],p["method"],p["method_mod"],p["method_off"]),flush=True)
        print("  this=%s vtable=%s(%s)"%(p["this_ptr"],p["vtable"],p["vtable_mod"]),flush=True)
        print("  this_data=%s"%p["this_data"],flush=True)
        print("  x1=%s x1_data=%s"%(p["x1"],p["x1_data"]),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<45 and len(rows)<4: time.sleep(0.5)
json.dump(rows,open("_callout_out.json","w"),indent=1)
print("\n[DONE] callouts=%d"%len(rows),flush=True)
