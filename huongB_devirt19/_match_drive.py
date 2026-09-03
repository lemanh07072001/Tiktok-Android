import frida, sys, time, subprocess, json, base64
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
PKG="com.zhiliaoapp.musically"; ACT="com.ss.android.ugc.aweme.splash.SplashActivity"
OVD="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 55
ATTACH_AT=int(sys.argv[2]) if len(sys.argv)>2 else 8
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
def pid():
    o=sh("pidof",PKG).strip(); return int(o.split()[0]) if o else 0
def disk_store():
    # list .ms* then base64 each -> {name: hexbytes}
    names=[x for x in sh("ls","-1A",OVD).split() if x.startswith(".ms")]
    out={}
    for n in names:
        b64=sh("base64",f"{OVD}/{n}").strip().replace("\n","")
        try: out[n]=base64.b64decode(b64).hex()
        except Exception: out[n]=None
    return out
print("force-stop+launch"); sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/{ACT}")
t0=time.time(); p=0
while time.time()-t0 < ATTACH_AT+25:
    p=pid()
    if p and (time.time()-t0)>=ATTACH_AT: break
    time.sleep(0.4)
if not p: print("NO PID"); sys.exit(1)
print(f"attach pid={p} t={time.time()-t0:.1f}")
dev=frida.get_usb_device(timeout=10); sess=dev.attach(p)
def on_msg(m,d):
    if m.get("type")=="send": print("  ",m["payload"])
    elif m.get("type")=="error": print("  ERR",m.get("description"))
scr=sess.create_script(open("_store_match.js").read()); scr.on("message",on_msg); scr.load()
print(f"collecting {SECS}s (store write ~t20-40)...")
t1=time.time(); nxt=0
while time.time()-t1 < SECS:
    e=int(time.time()-t1)
    if e>=nxt:
        subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True)
        nxt=e+7
    time.sleep(1)
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex); caps=[]
disk=disk_store()
json.dump({"caps":caps,"disk":disk},open("_match_out.json","w"))
print(f"captured {len(caps)} crypt ops; disk files {len(disk)}")
# byte-match: does any capture in/out contain a disk file's hex?
hits=[]
for n,dh in disk.items():
    if not dh: continue
    for c in caps:
        for side in ("in","out"):
            h=c.get(side)
            if not h: continue
            if dh==h or (len(dh)>=16 and dh in h) or (len(h)>=16 and h in dh):
                hits.append({"file":n,"side":side,"off":c["off"],"len":c["len"],"key":c.get("key"),"iv":c.get("iv"),"kb":c.get("kb"),"disklen":len(dh)//2})
print("=== HITS ===")
if hits:
    for h in hits: print(json.dumps(h))
else:
    print("NONE (no capture matched any on-disk store file)")
    # diagnostic: show length histogram + any store-sized captures
    from collections import Counter
    lc=Counter(c["len"] for c in caps)
    print("cap len hist:",dict(sorted(lc.items())))
    stores=set(len(v)//2 for v in disk.values() if v)
    print("disk sizes:",sorted(stores))
    near=[c for c in caps if c["len"] in stores]
    print(f"captures with store-matching LENGTH: {len(near)}")
    for c in near[:8]: print("  ",c["off"],c["len"],"in",str(c.get("in"))[:48],"key",c.get("key"))
sess.detach()
