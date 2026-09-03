import sys,os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; tag=sys.argv[1] if len(sys.argv)>1 else "run"
seq=[]
def on_msg(m,d):
    p=(m.get("payload") or {}); t=p.get("t")
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="seq":
        seq.append(p); print("  #%d slot16=%s rticket=%s"%(p["idx"],p["slot16"],p["rticket"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_slot16_seq.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] %s spawned %d"%(tag,pid),flush=True)
t0=time.time()
while time.time()-t0<95 and len(seq)<8: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(seq,open("_seq_%s.json"%tag,"w"))
print("[%s DONE] %d nonzero slot16: %s"%(tag,len(seq),[x["slot16"] for x in seq]),flush=True)
