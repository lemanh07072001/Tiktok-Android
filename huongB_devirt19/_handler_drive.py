import frida,subprocess,time,json,base64
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
    time.sleep(0.4)
pid=int(o.split()[0]); print("attach pid",pid,"t=%.1f"%(time.time()-t0))
dev=frida.get_usb_device(timeout=10); sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("k") in("READY","HANDLER_HOOKED","BLR","HHERR"): print(" ",json.dumps(p)[:180])
    elif m.get("type")=="error": print(" ERR",m.get("description"))
scr=sess.create_script(open("_handler.js").read()); scr.on("message",on); scr.load()
print("collecting 50s...")
t1=time.time(); nxt=0
while time.time()-t1<50:
    e=int(time.time()-t1)
    if e>=nxt: subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True); nxt=e+7
    time.sleep(1)
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex); caps=[]
d=disk()
json.dump({"caps":caps,"disk":d},open("_handler_out.json","w"),indent=1)
print("=== EVENTS ===", len(caps))
sess.detach()
