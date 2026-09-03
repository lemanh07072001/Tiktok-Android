import frida,sys,time,json,re
from gmssl import sm3, func
def SM3(b): return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(b)))
def bswap4(b): return b''.join(b[i:i+4][::-1] for i in range(0,len(b),4))
PKG="com.zhiliaoapp.musically"; DUR=int(sys.argv[1]) if len(sys.argv)>1 else 55
KNOWN=set()
for r in json.load(open("_corr_data.json")): KNOWN.add(bytes.fromhex(r["slot16"]))
for fn in ("_spawn_cleared.txt","_spawn_fresh.txt"):
    try:
        for ln in open(fn):
            m=re.search(r'\]\s+([0-9a-f]{32})\s',ln)
            if m: KNOWN.add(bytes.fromhex(m.group(1)))
    except: pass
print("[*] known pool:",len(KNOWN),flush=True)
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True)
sc=dev.attach(pid).create_script(open("_sm3_all.js",encoding="utf-8").read())
msgs=[]; states=set(); matches=[]
def chk_state(sthex):
    st=bytes.fromhex(sthex)
    # digest candidates from a 32-byte SM3 state (raw + per-word byteswap), lo/hi 16
    for name,c in (("st_lo",st[:16]),("st_hi",st[16:]),("st_lo_bs",bswap4(st[:16])),("st_hi_bs",bswap4(st[16:])),
                   ("st_lo_rev",st[:16][::-1]),("st_hi_rev",st[16:][::-1]),("st_full_bs_lo",bswap4(st)[:16])):
        if c in KNOWN: return (name,c.hex())
    return None
def chk_msg(mb):
    dig=SM3(mb)
    for name,c in (("m_lo",dig[:16]),("m_hi",dig[16:]),("m_lo_bs",bswap4(dig[:16])),("m_hi_bs",bswap4(dig[16:]))):
        if c in KNOWN: return (name,c.hex())
    return None
def on(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="info":print("[*]",p["msg"],flush=True);return
    if p.get("t")=="sm3msg":
        msgs.append(p["msg"]); r=chk_msg(bytes.fromhex(p["msg"]))
        if r: matches.append({"via":"msg","slot16":r[1],"slice":r[0],"msg":p["msg"]}); print("*** MSG MATCH",r,p["msg"][:160],flush=True)
    elif p.get("t")=="state":
        if p["st"] in states: return
        states.add(p["st"]); r=chk_state(p["st"])
        if r: matches.append({"via":"state","slot16":r[1],"slice":r[0],"state":p["st"]}); print("*** STATE MATCH",r,"state=",p["st"],flush=True)
sc.on("message",on); sc.load(); dev.resume(pid)
print("[*] resumed %ds"%DUR,flush=True)
t0=time.time()
while time.time()-t0<DUR: time.sleep(0.5)
json.dump({"matches":matches,"nmsgs":len(msgs),"nstates":len(states)},open("_sm3_spawn_out.json","w"),indent=1)
print("[DONE] msgs=%d states=%d matches=%d"%(len(msgs),len(states),len(matches)),flush=True)
