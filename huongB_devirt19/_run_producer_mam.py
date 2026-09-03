import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; res={"writes":[],"reads":[],"events":[]}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="arm": print("[ARM] hb%d slot=%s homes=%d %s pages=%s"%(p["hb"],p["slot16"],p["nhomes"],p["homes"],p["pages"]),flush=True); res["events"].append(p)
    elif t=="hb": print("[hb%d] slot=%s writes=%d"%(p["hb"],p["slot16"],p["writes_so_far"]),flush=True)
    elif t=="W": r=p["rec"]; print("   [W] %s  addr=%s home=%s d=%d"%(r["from"],r["addr"],r["home"],r["delta"]),flush=True); res["writes"].append(r)
    elif t=="err": print("   [err]",p["msg"],flush=True)
    elif t=="done": res["writes"]=p["writes"]; res["reads"]=p["reads"]; print("[DONE-JS] writes=%d"%len(p["writes"]),flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_slot16_producer_mam.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<150 and len(res["writes"])<40: time.sleep(0.5)
time.sleep(1)
try: sess.detach()
except: pass
json.dump(res,open("_producer_mam_out.json","w"))
# summarize write PCs
from collections import Counter
c=Counter(w["from"] for w in res["writes"])
print("\n[SUMMARY] distinct write-PCs to slot16 home:",flush=True)
for pc,n in c.most_common(): print("   %3dx  %s"%(n,pc),flush=True)
print("[DONE] %d writes saved"%len(res["writes"]),flush=True)
