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
scr=sess.create_script(open("_svc.js").read()); scr.on("message",on_msg); scr.load()
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
caps=[]
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex)
import json as _j
_j.dump(caps,open("_svc_out.json","w"),indent=1)
from collections import Counter
kc=Counter(c.get("k","?") for c in caps)
print("=== KINDS ===", dict(kc), "total", len(caps))
for c in caps:
    if c.get("k") in("OPEN","RENAME"): print(" ",_j.dumps(c)[:200])
for c in caps:
    if c.get("k") in("WRITE","WRITEV"):
        print(" WRITE", c.get("path","")[-40:], "len", c.get("len"), "head", str(c.get("head"))[:48])
        for fr in (c.get("bt") or [])[:8]: print("      ",fr)
sess.detach()
