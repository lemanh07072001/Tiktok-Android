import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_callout_data.js",encoding="utf-8").read())
co=[]; slots=[]
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="co":
        co.append(p); print("[CO #%d] ret=%s retderef=%s"%(p["n"],p["ret"],(p["retderef"] or "")[:64]),flush=True)
    if p.get("t")=="slot":
        slots.append(p["slot16"]); print("   [slot] %s"%p["slot16"],flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<45 and len(co)<12: time.sleep(0.5)
json.dump({"co":co,"slots":slots},open("_codata_out.json","w"),indent=1)
print("\n[DONE] callouts=%d slots=%d"%(len(co),len(slots)),flush=True)
