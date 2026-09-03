import sys,time,json,subprocess
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_evp_match.js'; OUT='cap.noindex/evp_match_init.json'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 40
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pidof():
    p=sh('shell','pidof',PKG); return int(p.split()[0]) if p.strip() else None

COMP=sh('shell','cmd','package','resolve-activity','--brief','-c','android.intent.category.LAUNCHER',PKG).splitlines()[-1].strip()
sh('shell','am','force-stop',PKG); time.sleep(1.0)
dev=frida.get_usb_device(timeout=10)
# launch, then race to attach on first pid sighting (init is slow under load => store read likely after hooks live)
sh('shell','am','start','-n',COMP)
pid=None; t0=time.time()
while time.time()-t0<15:
    pid=pidof()
    if pid: break
    time.sleep(0.12)
print('first pid @%.2fs'%(time.time()-t0), pid)
if not pid: print('NO PID'); sys.exit(1)

msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        msgs.append(m['payload']); p=m['payload']; print('  <<',p.get('tag'),p.get('base') or p.get('ev') or '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)

sess=None
for i in range(20):  # fast retries — beat the init store read
    try: sess=dev.attach(pid); break
    except Exception as e:
        # pid may have rotated (crash) — refresh
        np=pidof()
        if np and np!=pid: pid=np
        time.sleep(0.3)
if not sess: print('ATTACH FAILED'); sys.exit(1)
print('attached @%.2fs pid %d'%(time.time()-t0,pid))
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
print('oracle live @%.2fs'%(time.time()-t0))

tt=time.time()
while time.time()-tt<SECS:
    time.sleep(1.0)
    try:
        st=exp.status(); print('t%2.0f'%(time.time()-tt),'status',st)
    except Exception as e:
        print('t%2.0f script gone (%s) — streamed keys already captured'%(time.time()-tt,type(e).__name__)); break

try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
streamed_keys=[m for m in msgs if m.get('tag')=='KEY']
streamed_ivs=[m for m in msgs if m.get('tag')=='IV']
json.dump({'pid':pid,'msgs':msgs,'data':data,'streamed_keys':streamed_keys,'streamed_ivs':streamed_ivs}, open(OUT,'w'), indent=1)
print('STREAMED distinct keys:',len(streamed_keys),' ivs:',len(streamed_ivs))
for m in streamed_keys: print('   KEY kb=%s %s'%(m.get('kb'),m.get('key')))
for m in streamed_ivs: print('   IV  %s'%m.get('iv'))
k=data.get('keys',{}); print('WROTE',OUT,'| keys',len(k),'| ivs',len(data.get('ivs',{})),'| hits',len(data.get('hits',[])))
for kk in list(k): print('   key',kk)
for h in data.get('hits',[])[:8]: print('   HIT',h)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — no re-register')
