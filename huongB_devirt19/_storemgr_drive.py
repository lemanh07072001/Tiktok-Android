import frida,subprocess,time,json
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity")
t0=time.time()
while time.time()-t0<30:
    o=sh("pidof",PKG).strip()
    if o and time.time()-t0>=8: break
    time.sleep(0.4)
pid=int(o.split()[0]); print("attach pid",pid,"t=%.1f"%(time.time()-t0))
dev=frida.get_usb_device(timeout=10); sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("k")=="READY": print(" READY",p.get("meta"))
        elif p.get("k")=="PB": print(" PB out=",p.get("out")," args=",p.get("args"))
        elif p.get("k")=="RDR": print(" RDR",p.get("path"),"len",p.get("len"))
    elif m.get("type")=="error": print(" ERR",m.get("description"))
scr=sess.create_script(open("_storemgr.js").read()); scr.on("message",on); scr.load()
print("collecting 55s...")
t1=time.time(); nxt=0
while time.time()-t1<55:
    e=int(time.time()-t1)
    if e>=nxt: subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True); nxt=e+7
    time.sleep(1)
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex); caps=[]
json.dump(caps,open("_storemgr_out.json","w"),indent=1)
print("=== EVENTS ===", len(caps))
for c in caps:
    print("\n---",c["k"], c.get("out") or c.get("path"), "args",c.get("args"),"len",c.get("len"),"head",str(c.get("head"))[:40])
    for fr in (c.get("bt") or [])[:14]: print("    ",fr)
sess.detach()
