import frida,subprocess,time,json,os
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
sh("am","force-stop",PKG); time.sleep(1)
dev=frida.get_usb_device(timeout=10)
print("spawning...",flush=True)
pid=dev.spawn([PKG])
sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send" and m["payload"].get("k") in("INSTALLED","WAIT_DLOPEN","STORE","ERR"): print(" ",m["payload"],flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_mspspawn.js").read()); scr.on("message",on); scr.load()
dev.resume(pid)
print("resumed, collecting 50s (startup sdi_v2 recompute)...",flush=True)
t=time.time(); i=0
while time.time()-t<50:
    if i>6: subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","100"],capture_output=True)
    i+=1; time.sleep(2)
try: caps=scr.exports_sync.dump()
except Exception as e: print("dump exc",e,flush=True); caps=[]
json.dump({"caps":caps},open("_mspspawn_out.json","w"))
print("=== EVENTS ===",len(caps),flush=True)
os._exit(0)
