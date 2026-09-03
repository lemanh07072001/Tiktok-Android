#!/usr/bin/env python3
# DELAYED-ATTACH driver for _store_mode3.js.
# WHY delayed: attaching at t~0 injects frida-agent during the app's EGL context
# setup -> RenderThread SIGABRT ("EGL_NOT_INITIALIZED"). Wait until the UI is up
# (EGL already initialized) THEN attach. libmetasec_ov.so loads EARLY, so the
# oracle's tryPreload() installs INIT/CRYPT/KSCH hooks immediately (no dlopen wait).
# To fire store mode3: gentle HOME->foreground flush cycles force onPause store
# re-encrypt (encrypt path: in=PLAINTEXT). NO re-register (device_id+cookie persist).
import sys, time, json, subprocess, frida
PKG="com.zhiliaoapp.musically"
LAUNCHER="com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity"
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
OV="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 50
JS=open("_store_mode3.js").read()

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
def resumed_ok():
    r=adb("shell","su","0","dumpsys","activity","activities",t=10)
    o=r.stdout or ""
    return "ResumedActivity" in o and "com.zhiliaoapp.musically" in o and "MainActivity" in o
def store_mtimes():
    cmd="ls -la --time-style=+%H:%M:%S "+OV+" 2>/dev/null"
    r=adb("shell","su","0","sh","-c",cmd,t=10)
    return "\n".join(l for l in (r.stdout or "").replace("\r","").splitlines() if ".ms" in l)

msgs={"INIT":0,"CRYPT":0,"KSCH":0,"READY":0,"WAIT_DLOPEN":0}
dead={"v":False}
def on_msg(m,d):
    if m.get("type")=="send":
        p=m["payload"]; tag=p.get("tag")
        if tag in msgs: msgs[tag]+=1
        if tag in ("INIT","READY","WAIT_DLOPEN"): print("  <%s> %s"%(tag,{k:v for k,v in p.items() if k!='tag'}))
        if tag=="CRYPT": print("  <CRYPT len=%s key=%s>"%(p.get("len"),p.get("key")))
    elif m.get("type")=="error": print("  JS-ERR",m.get("description"))
def on_detached(reason,*a): dead["v"]=True; print("  !! session detached:",reason)

# 1) clean + launch
print("force-stop + launch")
adb("shell","su","0","am","force-stop",PKG); time.sleep(1)
adb("shell","su","0","am","start","-n",LAUNCHER)
dev=frida.get_usb_device(timeout=10); print("device:",dev)

# 2) wait for UI up (EGL initialized) before attach -> avoids RenderThread abort
print("waiting for UI up (avoid EGL-init race)...")
pid=None
for i in range(40):
    time.sleep(1)
    pid=pidof()
    if pid and resumed_ok() and i>=12:
        print("  UI up, pid=%d at ~%ds"%(pid,i+1)); break
else:
    pid=pidof(); print("  timeout waiting UI; pid=%s (attach anyway)"%pid)
if not pid: print("FATAL no pid"); sys.exit(1)
time.sleep(3)  # extra cushion after first frame

print("store mtime BEFORE:\n"+store_mtimes())

# 3) attach now (UI settled) + install (libmetasec already loaded)
sess=dev.attach(pid); sess.on("detached",on_detached)
script=sess.create_script(JS); script.on("message",on_msg); script.load()
print("attached pid=%d collecting %ds"%(pid,SECS))

# 4) collect + gentle flush cycles to force store re-encrypt
t0=time.time(); cyc=[t0+6, t0+24]; ci=0
while time.time()-t0 < SECS:
    time.sleep(3)
    if dead["v"]: print("  (session dead, stopping)"); break
    if ci<len(cyc) and time.time()>cyc[ci]:
        print("  -- flush #%d: HOME -> foreground --"%(ci+1))
        adb("shell","input","keyevent","KEYCODE_HOME"); time.sleep(4)
        adb("shell","su","0","am","start","-n",LAUNCHER); time.sleep(2); ci+=1
    try: st=script.exports_sync.status()
    except Exception: st={}
    print("  t%02d status=%s counts=%s"%(int(time.time()-t0),st,msgs))

try: data=script.exports_sync.dump()
except Exception as e: data=[]; print("dump err",e)
json.dump(data,open("_mode3_out.json","w"),indent=1)
print("\nstore mtime AFTER:\n"+store_mtimes())
print("EVENTS=%d  INIT=%d CRYPT=%d KSCH=%d  -> _mode3_out.json"%(len(data),msgs['INIT'],msgs['CRYPT'],msgs['KSCH']))
