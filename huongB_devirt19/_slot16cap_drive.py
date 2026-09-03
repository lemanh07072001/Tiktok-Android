import frida,subprocess,time,json,os
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
o=sh("pidof",PKG).strip()
if not o:
    sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity"); time.sleep(12); o=sh("pidof",PKG).strip()
pid=int(o.split()[0]); print("ATTACH pid",pid,flush=True)
dev=frida.get_usb_device(timeout=10); sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("k") in("CAPTURED","INSTALLED","READY","CAPERR"): print(" ",p,flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_slot16cap.js").read()); scr.on("message",on); scr.load()
print("navigating to trigger producer (feed signs)...",flush=True)
t=time.time()
while time.time()-t<45:
    subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","100"],capture_output=True)
    try:
        if scr.exports_sync.status()["has"]: break
    except Exception as e: print("poll exc",str(e)[:40],flush=True); break
    time.sleep(2)
try: st=scr.exports_sync.status()
except: print("script dead"); os._exit(1)
if not st["has"]: print("NO CAPTURE"); os._exit(1)
meta=scr.exports_sync.meta(); closure=scr.exports_sync.closure()
print("captured base=%s url=%s closure=%d"%(meta["base"],meta["url"],len(closure)),flush=True)
msize=meta["msize"]; chunks=[]; step=0x40000
for off in range(0,msize,step):
    chunks.append((off,scr.exports_sync.sochunk(off,min(step,msize-off))))
print("pulled .so %dB"%msize,flush=True)
json.dump({"meta":meta,"closure":closure,"so_chunks":chunks},open("_slot16cap_out.json","w"))
print("=== SAVED ===",flush=True); os._exit(0)
