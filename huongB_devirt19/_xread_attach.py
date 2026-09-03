import frida,subprocess,time,json,os
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
o=sh("pidof",PKG).strip()
if not o:
    sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity"); time.sleep(12); o=sh("pidof",PKG).strip()
pid=int(o.split()[0]); print("attach RUNNING pid",pid,flush=True)
dev=frida.get_usb_device(timeout=10)
sess=None
for _ in range(5):
    try: sess=dev.attach(pid); break
    except Exception as e: print("retry",str(e)[:40],flush=True); time.sleep(2)
if not sess: print("FAIL"); os._exit(1)
def on(m,d):
    if m.get("type")=="send" and m["payload"].get("k") in("H","E","READY"): print(" ",m["payload"],flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_xread.js").read()); scr.on("message",on); scr.load()
print("collecting 45s + navigation to trigger store read/write...",flush=True)
t=time.time(); i=0
while time.time()-t<45:
    # navigation to trigger settings/store access: swipe, back, tab switches
    subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","100"],capture_output=True)
    if i%3==0: subprocess.run([ADB,"shell","input","tap","540","2200"],capture_output=True)  # bottom tab
    if i%4==0: subprocess.run([ADB,"shell","input","keyevent","KEYCODE_BACK"],capture_output=True)
    i+=1; time.sleep(2)
try: caps=scr.exports_sync.dump()
except Exception as e: print("dump exc",e,flush=True); caps=[]
json.dump({"caps":caps},open("_xread_out.json","w"))
print("=== EVENTS ===",len(caps),flush=True)
os._exit(0)
