import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; evs=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="ev": evs.append(p)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_phase_diag.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
# stop shortly after we see the first SM3_slot16 (one full heartbeat mapped)
while time.time()-t0<70:
    if any(e["tag"]=="SM3_slot16" for e in evs) and time.time()-t0>12: break
    time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(evs,open("_phase_diag_out.json","w"))
# print the window around the first slot16, grouped by tid
first=None
for i,e in enumerate(evs):
    if e["tag"]=="SM3_slot16": first=i; break
lo=max(0, (first or 40)-40); hi=(first or 0)+3
print("\n[TIMELINE around first slot16]  (tag @tid : extra)",flush=True)
for e in evs[lo:hi if first else 60]:
    print("  #%-4d %-13s @%-7s %s"%(e["seq"],e["tag"],e["tid"],e.get("extra") or ""),flush=True)
from collections import Counter
print("\n[event counts]",dict(Counter(e["tag"] for e in evs)),flush=True)
print("[tids seen]",dict(Counter(e["tid"] for e in evs)),flush=True)
