import sys,time,json,subprocess
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_evp_match.js'
OUT='cap.noindex/evp_match_out.json'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 50

def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pidof():
    p=sh('shell','pidof',PKG)
    return int(p.split()[0]) if p.strip() else None

# passive launch via am start -n (monkey LAUNCHER path is flaky on this AVD); no -D => no JDWP anti-debug
COMP=sh('shell','cmd','package','resolve-activity','--brief','-c','android.intent.category.LAUNCHER',PKG).splitlines()[-1].strip()
if pidof() is None:
    print('launch:', COMP, '::', sh('shell','am','start','-n',COMP) or '(ok)')
else:
    print('already running pid', pidof())

def wait_stable(win=4, tot=100):
    t0=time.time(); last=None; since=None
    while time.time()-t0<tot:
        p=pidof()
        if p and p==last:
            if since and time.time()-since>=win: return p
        else:
            last=p; since=time.time() if p else None
        time.sleep(1)
    return last
pid=wait_stable()
print('stable pid', pid)
if not pid: print('NO PID'); sys.exit(1)

msgs=[]
def on_msg(m,d):
    if m.get('type')=='send': msgs.append(m['payload']); 
    else: msgs.append({'tag':'ERR','m':str(m)})
    if m.get('type')=='send': print('  <<', m['payload'].get('tag'), m['payload'].get('base') or m['payload'].get('ev') or '')

dev=frida.get_usb_device(timeout=10)
sess=None
for i in range(8):
    try: sess=dev.attach(pid); break
    except Exception as e:
        print('attach retry',i,repr(e))
        try: dev.enumerate_processes()
        except: pass
        time.sleep(1.5)
if not sess: print('ATTACH FAILED'); sys.exit(1)
print('attached.')
scr=sess.create_script(open(JS).read())
scr.on('message', on_msg)
scr.load()
exp = getattr(scr,'exports_sync',None) or scr.exports

t0=time.time(); swipes=0
while time.time()-t0<SECS:
    sh('shell','input','swipe','540','1500','540','300','100'); swipes+=1
    time.sleep(2.2)
    try:
        st=exp.status()
        print('t%2.0f'%(time.time()-t0),'status', st)
        if st.get('nhits',0)>0:
            print('*** HIT — store key content-matched, pinning done ***')
            time.sleep(1); break
    except Exception as e:
        print('status exc', repr(e))

try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
json.dump({'pid':pid,'swipes':swipes,'msgs':msgs,'data':data}, open(OUT,'w'), indent=1)
k=data.get('keys',{}); print('WROTE',OUT,'| distinct keys',len(k),'| ivs',len(data.get('ivs',{})),'| hits',len(data.get('hits',[])))
for kk in list(k)[:12]: print('   key',kk)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — app left running, NOT killed, NO re-register')
