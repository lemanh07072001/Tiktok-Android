import frida,subprocess,time,json,base64,os,hashlib
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
OVD="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
def disk():
    names=[x for x in sh("ls","-1A",OVD).split() if x.startswith(".ms")]
    return {n:base64.b64decode(sh("base64",f"{OVD}/{n}").strip().replace("\n","")).hex() for n in names}
sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity")
t0=time.time()
while time.time()-t0<30:
    o=sh("pidof",PKG).strip()
    if o and time.time()-t0>=8: break
    time.sleep(0.3)
pid=int(o.split()[0]); print("attach pid",pid,flush=True)
dev=frida.get_usb_device(timeout=10)
sess=None
for _ in range(4):
    try: sess=dev.attach(pid); break
    except Exception as e: print("retry",e,flush=True); time.sleep(2)
if not sess: os._exit(1)
def on(m,d):
    if m.get("type")=="send" and m["payload"].get("k") in("HOOK","ERR","READY"): print(" ",m["payload"],flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_regpair.js").read()); scr.on("message",on); scr.load()
print("collecting 50s...",flush=True)
t1=time.time(); nxt=0
while time.time()-t1<50:
    e=int(time.time()-t1)
    if e>=nxt: subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True); nxt=e+6
    time.sleep(1)
try: strs=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex,flush=True); strs=[]
d=disk()
import json as J
J.dump({"strs":strs,"disk":d},open("_regpair_out.json","w"),flush=False) if False else J.dump({"strs":strs,"disk":d},open("_regpair_out.json","w"))
print("=== STRINGS ===",len(strs),flush=True)
os._exit(0)
