#!/usr/bin/env python3
# Run _find_producer.js, collect which candidate VM-call's output buffer contains each nonzero slot16.
import frida, sys, time, collections, json
pid=int(sys.argv[1]) if len(sys.argv)>1 else 5471
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
sess=dev.attach(pid)
sc=sess.create_script(open("_find_producer.js",encoding="utf-8").read())
hits=[]; tally=collections.Counter(); nz=[]; zc=[0]
def on(msg,data):
    if msg.get("type")!="send": return
    p=msg["payload"]
    if p.get("t")=="info": print("[*]",p["msg"]); return
    if p.get("t")=="sm3":
        f=p["found"]; hits.append(p)
        if p.get("zero"): zc[0]+=1
        else:
            nz.append(p)
            for k in f: tally[k]+=1
            print("[NONZERO] %s found=%s q=%s"%(p["slot16"], f, (p.get("query") or "")[-60:]),flush=True)
sc.on("message",on); sc.load()
DUR=int(sys.argv[2]) if len(sys.argv)>2 else 90
print("[*] collecting %ds ..."%DUR,flush=True)
t0=time.time()
while time.time()-t0<DUR: time.sleep(0.5)
print("\n=== TALLY (which candidate buffer held the slot16) ===")
for k,v in tally.most_common(): print("   %s : %d/%d nonzero-slots"%(k,v,len(nz)))
print("total slots seen: %d (zero=%d, nonzero=%d)"%(len(hits),zc[0],len(nz)))
json.dump(nz,open("_nonzero_slots.json","w"),indent=1)
print("saved %d nonzero -> _nonzero_slots.json"%len(nz))
try: sess.detach()
except: pass
