import sys,time,json,subprocess,frida
PKG='com.zhiliaoapp.musically'
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 25
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
sessions=[]; scripts=[]; got={'main':False}
def on_msg(m,data):
    if m.get('type')=='send': print('EVT',json.dumps(m['payload'])[:260],flush=True)
    elif m.get('type')=='error': print('ERR',m.get('stack','')[:300],flush=True)
dev=frida.get_usb_device(timeout=5)
def on_spawn(spawn):
    try:
        ident=spawn.identifier or ''
        if ident==PKG and not got['main']:
            got['main']=True
            print('SPAWN main pid',spawn.pid,ident,flush=True)
            s=dev.attach(spawn.pid); sc=s.create_script(open('_store_oracle8.js').read())
            sc.on('message',on_msg); sc.load(); sessions.append(s); scripts.append(sc)
            print('injected, resuming',flush=True)
            dev.resume(spawn.pid)
        else:
            dev.resume(spawn.pid)
    except Exception as e:
        print('spawn-handler exc',e,flush=True)
        try: dev.resume(spawn.pid)
        except: pass
dev.on('spawn-added',on_spawn)
dev.enable_spawn_gating()
print('spawn gating ON; force-stop + launch',flush=True)
subprocess.run([ADB,'shell','am','force-stop',PKG])
time.sleep(1)
subprocess.run([ADB,'shell','monkey','-p',PKG,'-c','android.intent.category.LAUNCHER','1'],
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('launch issued, collecting %ds'%DUR,flush=True)
time.sleep(DUR)
allev=[]
for sc in scripts:
    try: allev += sc.exports_sync.dump().get('events',[])
    except Exception as e: print('dumpexc',e,flush=True)
json.dump({'events':allev},open('_oracle8_out.json','w'),indent=1)
from collections import Counter
c=Counter(e.get('t') for e in allev)
print('TOTAL',len(allev),'KINDS',dict(c),flush=True)
try: dev.disable_spawn_gating()
except: pass
