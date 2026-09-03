import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
# known pool
KNOWN=set()
d=json.load(open("_singleshot.json"))
for s in d["slots"]:
    if s["slot16"]!="00"*16: KNOWN.add(s["slot16"])
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_f_output.js",encoding="utf-8").read())
rows=[]
def find_slot(hexstr):
    if not hexstr: return None
    for k in KNOWN:
        if k in hexstr: return k
    return None
def on(m,dd):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="out":
        rows.append(p)
        hit=find_slot(p["outbuf"])
        print("\n[OUT #%d] outbuf=%s%s"%(p["n"],p["outbuf"][:64], " SLOT@outbuf!" if hit else ""),flush=True)
        for dr in p["derefs"]:
            h=find_slot(dr["data"])
            print("   off=%d ptr=%s data=%s%s"%(dr["off"],dr["ptr"],(dr["data"] or "")[:64]," <== SLOT16=%s"%h if h else ""),flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<45 and len(rows)<6: time.sleep(0.5)
print("\n[DONE] outs=%d"%len(rows),flush=True)
