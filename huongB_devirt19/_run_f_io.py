import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; evs=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t in ("F","ser"): evs.append(p)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_f_io.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<75 and len([e for e in evs if e['t']=='ser'])<6: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(evs,open("_f_io_out.json","w"))
print("\n[SEQUENCE]  (F prog / dval=F-output-string-data ; SER=serialized slot16)",flush=True)
for e in evs[:44]:
    if e["t"]=="F": print("  F#%-3d prog=%s mat=%s"%(e["seq"],e["prog"],(e.get("mat") or '')[:40]),flush=True); print("        outpost=%s"%e.get("outpost"),flush=True); print("        dval=%s"%(e.get("dval")),flush=True)
    else: print("  SER#%-3d slot16=%s"%(e["seq"],e["slot16"]),flush=True)
# check if any F output == any ser slot16
sers=set(e["slot16"] for e in evs if e["t"]=="ser")
fouts=[]
for e in evs:
    if e["t"]=="F":
        for k in ("dval","outpre","outpost","dval32"):
            v=e.get(k)
            if v:
                for j in range(0,len(v)-31,2):
                    fouts.append(v[j:j+32])
match=sers & set(fouts)
print("\n[MATCH] serialized slot16 values also appearing in F output/bufs:",match if match else "NONE",flush=True)
print("[DONE] F events=%d, ser=%d"%(len([e for e in evs if e['t']=='F']),len(sers)),flush=True)
