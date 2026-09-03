import frida, sys, time, subprocess, json
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
PKG="com.zhiliaoapp.musically"
ACT="com.ss.android.ugc.aweme.splash.SplashActivity"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 70
ATTACH_AT=int(sys.argv[2]) if len(sys.argv)>2 else 8
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout.strip()
def pid(): 
    o=sh("pidof",PKG); return int(o.split()[0]) if o.strip() else 0
print("force-stop+launch"); sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/{ACT}")
t0=time.time(); p=0
while time.time()-t0 < ATTACH_AT+20:
    p=pid()
    if p and (time.time()-t0)>=ATTACH_AT: break
    time.sleep(0.4)
if not p: print("NO PID"); sys.exit(1)
print(f"attach pid={p} at t={time.time()-t0:.1f}")
dev=frida.get_usb_device()
sess=dev.attach(p)
evs=[]
def on_msg(m,d):
    if m.get("type")=="send":
        pl=m["payload"]; evs.append(pl)
        k=pl.get("k","")
        if k in("READY","JAVA_READY","JAVA_ERR","NO_JAVA"): print("  ",pl)
        elif k in("OPEN","WRITE","WRITEV","MMAP","JOPEN","JWRITE"): print("  *",json.dumps(pl)[:160])
    elif m.get("type")=="error": print("  ERR",m.get("description"))
src=open("_wpath.js").read()
scr=sess.create_script(src); scr.on("message",on_msg); scr.load()
print(f"collecting {SECS}s (store writes ~t20-40)...")
t1=time.time(); nxt=0
while time.time()-t1 < SECS:
    e=int(time.time()-t1)
    if e>=nxt:
        # gentle swipe to nudge feed load (won't re-register)
        subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True)
        nxt=e+8
    time.sleep(1)
try: log=scr.exports_sync.dump()
except Exception as ex: log=evs; print("dump exc",ex)
json.dump(log,open("_wpath_out.json","w"),indent=1)
kinds={}
for e in log: kinds[e.get("k","?")]=kinds.get(e.get("k","?"),0)+1
print("KINDS",kinds,"total",len(log))
sess.detach()
