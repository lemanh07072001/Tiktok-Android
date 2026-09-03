import sys,time,json,subprocess
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_evp_match.js'
OUT='cap.noindex/evp_match_out.json'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 50
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()

# make sure app is stopped so spawn is a true cold start (force-stop keeps /data => no re-register)
sh('shell','am','force-stop',PKG); time.sleep(1)

msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        msgs.append(m['payload']); p=m['payload']
        print('  <<', p.get('tag'), p.get('base') or p.get('ev') or '')
    else:
        msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR', m)

dev=frida.get_usb_device(timeout=10)
pid=None
for i in range(5):
    try: pid=dev.spawn([PKG]); break
    except Exception as e:
        print('spawn retry',i,repr(e)); time.sleep(2)
if pid is None: print('SPAWN FAILED'); sys.exit(2)
print('spawned pid', pid)
sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
scr.on('message', on_msg)
scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
dev.resume(pid)
print('resumed — hooks live pre-init, catching cold-start store read')

t0=time.time(); swipes=0
# let init settle a moment (store read is first ~2s), then drive feed
time.sleep(6)
while time.time()-t0<SECS:
    sh('shell','input','swipe','540','1500','540','300','100'); swipes+=1
    time.sleep(2.2)
    try:
        st=exp.status(); print('t%2.0f'%(time.time()-t0),'status',st)
        if st.get('nhits',0)>0: print('*** HIT — store key content-matched ***'); time.sleep(1); break
    except Exception as e: print('status exc',repr(e))

try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
json.dump({'pid':pid,'swipes':swipes,'msgs':msgs,'data':data}, open(OUT,'w'), indent=1)
k=data.get('keys',{}); print('WROTE',OUT,'| keys',len(k),'| ivs',len(data.get('ivs',{})),'| hits',len(data.get('hits',[])))
for kk in list(k)[:16]: print('   key',kk)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — app left running, NO re-register')
