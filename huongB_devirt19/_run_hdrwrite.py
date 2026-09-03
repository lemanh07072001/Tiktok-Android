import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 70
writes=[]; loc=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="hdrloc": loc.append(p); print("[HDR-ARMED] base=%s slot16=%s"%(p["hdrBase"],p["slot16"]),flush=True)
    elif t=="write":
        writes.append(p); print("[WRITE] prog=%s lr=%s"%(p["prog"],p["lr"]),flush=True)
        print("   before:",p["before"],flush=True); print("   after :",p["after"],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID); sc=sess.create_script(open("_f_hdrwrite.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] attached %d %ds"%(PID,SECS),flush=True)
t0=time.time()
while time.time()-t0<SECS and len(writes)<8: time.sleep(0.3)
try: sess.detach()
except: pass
json.dump({"writes":writes,"loc":loc},open("_hdrwrite_out.json","w")); print("[DONE] writes=%d"%len(writes),flush=True)
