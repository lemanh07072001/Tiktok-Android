#!/usr/bin/env python3
# Capture all SM3 messages; offline recompute digests and search for known slot16 values.
import frida, sys, time, json
from gmssl import sm3, func
def SM3(b): return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(b)))
def bswap4(b): return b''.join(b[i:i+4][::-1] for i in range(0,len(b),4))
pid=int(sys.argv[1]); DUR=int(sys.argv[2]) if len(sys.argv)>2 else 60
# known slot16 pool (from corr_data + captures)
KNOWN=set()
try:
    for r in json.load(open("_corr_data.json")): KNOWN.add(bytes.fromhex(r["slot16"]))
except: pass
import re
for fn in ("_spawn_cleared.txt","_spawn_fresh.txt"):
    try:
        for ln in open(fn):
            m=re.search(r'\]\s+([0-9a-f]{32})\s',ln)
            if m: KNOWN.add(bytes.fromhex(m.group(1)))
    except: pass
print("[*] known slot16 pool size:",len(KNOWN))

dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_sm3_all.js",encoding="utf-8").read())
msgs=[]; matches=[]
def check(msg_bytes):
    dig=SM3(msg_bytes)
    for name,cand in (("lo",dig[:16]),("hi",dig[16:]),("lo_bs",bswap4(dig[:16])),("hi_bs",bswap4(dig[16:])),
                      ("lo_rev",dig[:16][::-1]),("hi_rev",dig[16:][::-1])):
        if cand in KNOWN:
            return (name, cand.hex(), dig.hex())
    return None
def on(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    if p.get("t")=="info": print("[*]",p["msg"]); return
    if p.get("t")=="sm3msg":
        mb=bytes.fromhex(p["msg"]); msgs.append(p["msg"])
        r=check(mb)
        if r:
            matches.append({"slot16":r[1],"slice":r[0],"digest":r[2],"mlen":p["mlen"],"msg":p["msg"]})
            print("\n*** F MATCH: slot16=%s = SM3(msg)[%s]  mlen=%d"%(r[1],r[0],p["mlen"]))
            print("    msg=%s"%p["msg"][:200],flush=True)
sc.on("message",on); sc.load()
print("[*] collecting %ds"%DUR)
t0=time.time()
while time.time()-t0<DUR: time.sleep(0.5)
json.dump({"matches":matches,"nmsgs":len(msgs),"sample":msgs[:40]},open("_sm3_all_out.json","w"),indent=1)
print("\n[DONE] total SM3 msgs=%d, F-matches=%d -> _sm3_all_out.json"%(len(msgs),len(matches)))
