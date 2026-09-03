#!/usr/bin/env python3
# EARLY-ATTACH driver for _store_mode3b.js (oracle v9).
# WHY earlier than v8's t~15: store mode3 DECRYPT fires ONCE at cold-launch when the
# SDK reads the .ms* file (RDR -> in-place mode3 decrypt: in=ciphertext=disk, out=plaintext).
# Attaching at t~15 (after MainActivity resumed) MISSES that cold read -> only the
# request-signing firehose is seen. So attach at the EARLIEST EGL-safe point (~t6):
# EGL context is created in the first ~3s (the t0-attach abort proved this), so t>=6
# is past EGL init but still inside the SDK-init window where the store is first read.
import sys, time, json, subprocess, frida
PKG="com.zhiliaoapp.musically"
LAUNCHER="com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity"
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
OV="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 45
ATTACH_AT=int(sys.argv[2]) if len(sys.argv)>2 else 6   # seconds after launch (EGL-safe)
JS=open("_store_mode3b.js").read()

def adb(*a, t=15):
    try: return subprocess.run([ADB]+list(a),capture_output=True,text=True,timeout=t)
    except Exception as e:
        class R: stdout=""; stderr="ERR "+str(e)
        return R()
def pidof():
    r=adb("shell","su","0","pidof",PKG,t=8)
    for tok in (r.stdout or "").replace("\r","").strip().split():
        if tok.isdigit(): return int(tok)
    return None
def store_mtimes():
    cmd="ls -la --time-style=+%H:%M:%S "+OV+" 2>/dev/null"
    r=adb("shell","su","0","sh","-c",cmd,t=10)
    return "\n".join(l for l in (r.stdout or "").replace("\r","").splitlines() if ".ms" in l)

msgs={"INIT":0,"CRYPT":0,"KSCH":0,"RDR":0,"READY":0,"WAIT_DLOPEN":0}
store_hits=[]
dead={"v":False}
def on_msg(m,d):
    if m.get("type")=="send":
        p=m["payload"]; tag=p.get("tag")
        if tag in msgs: msgs[tag]+=1
        if tag=="RDR": print("  <RDR store=%s len=%s head=%s>"%(p.get("store"),p.get("len"),(p.get("head") or "")[:32]))
        if tag=="READY": print("  <READY base=%s>"%p.get("base"))
        if tag=="WAIT_DLOPEN": print("  <WAIT_DLOPEN>")
        if tag=="INIT" and p.get("store"): print("  <INIT STORE=%s key=%s iv=%s>"%(p.get("store"),p.get("key"),p.get("iv")))
        if tag=="CRYPT" and p.get("STORE"):
            store_hits.append(p); print("  ***STORE CRYPT store=%s len=%s key=%s***"%(p.get("store"),p.get("len"),p.get("key")))
    elif m.get("type")=="error": print("  JS-ERR",m.get("description"))
def on_detached(reason,*a): dead["v"]=True; print("  !! detached:",reason)

print("force-stop + cold launch")
adb("shell","su","0","am","force-stop",PKG); time.sleep(1)
print("store mtime BEFORE:\n"+store_mtimes())
t_launch=time.time()
adb("shell","su","0","am","start","-n",LAUNCHER)
dev=frida.get_usb_device(timeout=10)

# poll pid FAST; attach at earliest EGL-safe point (elapsed>=ATTACH_AT)
pid=None
while time.time()-t_launch < 30:
    time.sleep(0.4); pid=pidof()
    if pid and (time.time()-t_launch)>=ATTACH_AT: break
if not pid: print("FATAL no pid"); sys.exit(1)
el=time.time()-t_launch
print("attaching pid=%d at ~%.1fs (EGL-safe, catch store cold-read)"%(pid,el))

try:
    sess=dev.attach(pid); sess.on("detached",on_detached)
    script=sess.create_script(JS); script.on("message",on_msg); script.load()
except Exception as e:
    print("ATTACH/LOAD FAIL:",e); sys.exit(2)
print("attached, collecting %ds"%SECS)

# light interaction: scroll feed to trigger settings reads (store cache misses)
t0=time.time(); nudged=0
while time.time()-t0 < SECS:
    time.sleep(3)
    if dead["v"]: print("  (dead, stop)"); break
    if nudged<3:
        adb("shell","input","swipe","540","1400","540","500","200"); nudged+=1
    try: st=script.exports_sync.status()
    except Exception: st={}
    print("  t%02d status=%s counts=%s store_hits=%d"%(int(time.time()-t0),st,msgs,len(store_hits)))

try: data=script.exports_sync.dump()
except Exception as e: data=[]; print("dump err",e)
json.dump(data,open("_mode3b_out.json","w"),indent=1)
try: so=script.exports_sync.storeonly()
except Exception: so=[]
json.dump(so,open("_mode3b_store.json","w"),indent=1)
print("\nstore mtime AFTER:\n"+store_mtimes())
print("EVENTS=%d INIT=%d CRYPT=%d KSCH=%d RDR=%d storeTagged=%d -> _mode3b_out.json / _mode3b_store.json"
      %(len(data),msgs['INIT'],msgs['CRYPT'],msgs['KSCH'],msgs['RDR'],len(so)))
