import frida,sys,time
PKG="com.zhiliaoapp.musically"
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_dbg_f.js",encoding="utf-8").read())
def on(m,d):
    if m.get("type")=="send": print("[*]",m["payload"].get("msg"),flush=True)
    elif m.get("type")=="error": print("[ERR]",m.get("stack","")[:200],flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
time.sleep(45)
