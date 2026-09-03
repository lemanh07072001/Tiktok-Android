import sys,time,json,subprocess,frida
PKG='com.zhiliaoapp.musically'
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 25
src=open('_store_oracle8.js').read()
def on_msg(m,data):
    if m.get('type')=='send': print('EVT',json.dumps(m['payload'])[:260],flush=True)
    elif m.get('type')=='error': print('ERR',m.get('stack','')[:300],flush=True)
dev=frida.get_usb_device(timeout=5)
subprocess.run([ADB,'shell','am','force-stop',PKG])
time.sleep(0.6)
subprocess.run([ADB,'shell','monkey','-p',PKG,'-c','android.intent.category.LAUNCHER','1'],
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
t0=time.time(); sess=None; tries=0
while time.time()-t0 < 8:
    tries+=1
    try:
        sess=dev.attach(PKG); break
    except Exception:
        time.sleep(0.02)
if not sess:
    print('ATTACH FAILED after',tries,'tries',flush=True); raise SystemExit
dt=(time.time()-t0)*1000
print('ATTACHED after %.0fms, %d tries'%(dt,tries),flush=True)
scr=sess.create_script(src); scr.on('message',on_msg); scr.load()
print('injected, collecting %ds'%DUR,flush=True)
time.sleep(DUR)
try: ev=scr.exports_sync.dump().get('events',[])
except Exception as e: ev=[]; print('dumpexc',e,flush=True)
json.dump({'events':ev,'attach_ms':dt},open('_race_out.json','w'),indent=1)
from collections import Counter
print('TOTAL',len(ev),'KINDS',dict(Counter(e.get('t') for e in ev)),flush=True)
