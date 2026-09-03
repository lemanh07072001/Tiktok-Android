#!/usr/bin/env python3
# Spawn app suspended under frida, load _correlate_seq.js, resume, capture cold-start signs.
# Goal: see if fresh device-register F(PSK,seed)->slot16 runs on cold start (nonzero slots w/ NEW values).
import frida, sys, time, json
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 45
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
print("[*] spawning", PKG)
pid=dev.spawn([PKG])
print("[*] spawned pid",pid)
sess=dev.attach(pid)
sc=sess.create_script(open("_correlate_seq.js",encoding="utf-8").read())
rows=[]
def on(msg,data):
    if msg.get("type")!="send": return
    p=msg["payload"]
    if p.get("t")=="info": print("[*]",p["msg"]); return
    if p.get("t")=="sm3":
        rows.append(p)
        tag="REG" if p.get("reg") else "   "
        print("[%s] %s lr=%s q=%s"%(tag, p["slot16"], p.get("lrseq"), p.get("qhead")),flush=True)
sc.on("message",on); sc.load()
dev.resume(pid)
print("[*] resumed; collecting %ds"%DUR)
t0=time.time()
while time.time()-t0<DUR: time.sleep(0.5)
json.dump(rows,open("_spawn_seq.json","w"),indent=1)
print("\n[DONE] nonzero signs=%d -> _spawn_seq.json"%len(rows))
try: sess.detach()
except: pass
