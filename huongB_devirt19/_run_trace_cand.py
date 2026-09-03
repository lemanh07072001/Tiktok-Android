import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 45
JS=sys.argv[3] if len(sys.argv)>3 else "_vm_trace_cand.js"
data={"start":None,"end":None,"tr":[],"pool":[]}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="start": data["start"]=p; print("[START] prog=%s rfBase=%s"%(p["prog"],p["rfBase"]),flush=True)
    elif t=="end": data["end"]=p; data["pool"]=p.get("pool",[]); print("[END] steps=%d poolN=%d"%(p["steps"],len(p.get("pool",[]))),flush=True)
    elif t=="tr": data["tr"].extend(p["rows"])
    elif t in("poollate",): data["pool"]=p["pool"]; print("[POOL] n=%d"%len(p["pool"]),flush=True)
    elif t=="done": print("[DONE-script]",flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID); sc=sess.create_script(open(JS,encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] attached %d %ds JS=%s"%(PID,SECS,JS),flush=True)
t0=time.time()
while time.time()-t0<SECS and data["end"] is None: time.sleep(0.3)
time.sleep(2)
try: sess.detach()
except: pass
json.dump(data,open("_trace_cand_out.json","w"))
print("[SAVED] steps=%d tr=%d pool=%d"%((data["end"] or {}).get("steps",0),len(data["tr"]),len(data["pool"])),flush=True)
