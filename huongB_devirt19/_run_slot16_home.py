import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"
snaps=[]; info=[]; stable={}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="slot" and p.get("kind")=="ZERO": print("[slot] ZERO (normal request)",flush=True)
    elif t=="snap":
        snaps.append(p)
        print("[SNAP %d] slot16=%s homes=%d"%(p["n"],p["slot16"],p["nhomes"]),flush=True)
        for h in p["homes"][:40]: print("     ",h["addr"],h["region"],flush=True)
    elif t=="stable":
        stable.update(p["hist"])
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
print("[*] device",dev,flush=True)
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sess=dev.attach(pid); sc=sess.create_script(open("_slot16_home.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] resumed",flush=True)
t0=time.time()
while time.time()-t0<110 and len(snaps)<6: time.sleep(0.4)
try: sess.detach()
except: pass
# analyze stability from per-snapshot homes (addr seen across >=2 snapshots = persistent cache home)
from collections import Counter
hist=Counter()
for sp in snaps:
    for h in sp.get("homes",[]): hist[h["addr"]]+=1
persistent={a:c for a,c in hist.items() if c>=2}
stable=dict(hist)
print("\n[ANALYSIS] total snapshots=%d"%len(snaps),flush=True)
print("[ANALYSIS] addresses holding slot16 seen in >=2 snapshots (STABLE homes): %d"%len(persistent),flush=True)
for a,c in sorted(persistent.items(),key=lambda x:-x[1])[:30]: print("   STABLE",a,"count",c,flush=True)
json.dump({"snaps":snaps,"stable_hist":stable,"persistent":persistent},open("_slot16_home_out.json","w"))
print("[DONE] saved _slot16_home_out.json",flush=True)
