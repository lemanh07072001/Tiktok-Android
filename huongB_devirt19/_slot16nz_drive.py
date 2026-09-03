import frida,subprocess,time,json,os
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
sh("am","force-stop",PKG); time.sleep(1)
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]); sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("k") in("CAPTURED","INSTALLED","READY"): print(" ",p,flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_slot16nz.js").read()); scr.on("message",on); scr.load()
dev.resume(pid)
print("resumed, waiting for NONZERO slot16 (register/heartbeat)...",flush=True)
t=time.time()
while time.time()-t<90:
    try:
        if scr.exports_sync.status()["has"]: break
    except Exception as e: print("dead:",str(e)[:40],flush=True); os._exit(1)
    subprocess.run([ADB,'shell','input','swipe','540','1400','540','400','100'],capture_output=True)
    time.sleep(2)
try: st=scr.exports_sync.status()
except: os._exit(1)
if not st["has"]: print("NO NONZERO in 90s"); os._exit(1)
meta=scr.exports_sync.meta(); closure=scr.exports_sync.closure()
print("captured url=%s slot16=%s off=%d drv=%s"%(meta["url"],meta["slot16"],meta["slot16_off"],meta.get("drvSlot")),flush=True)
msize=meta["msize"]; chunks=[]
for off in range(0,msize,0x40000): chunks.append((off,scr.exports_sync.sochunk(off,min(0x40000,msize-off))))
print("pulled .so %dB"%msize,flush=True)
json.dump({"meta":meta,"closure":closure,"so_chunks":chunks},open("_slot16nz_out.json","w"))
print("=== SAVED ===",flush=True); os._exit(0)
