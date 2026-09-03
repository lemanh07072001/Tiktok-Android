import sys,time,json,subprocess,os
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'; JS='_store_write.js'; OUT='cap.noindex/store_write.json'
OV='/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 50
os.makedirs('cap.noindex',exist_ok=True)
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def md5s():
    o=sh('shell','su','0','find',OV,'-maxdepth','1','-name','.ms*','-exec','md5sum','{}','+')
    d={}
    for l in o.splitlines():
        p=l.split()
        if len(p)>=2: d[p[1].split('/')[-1]]=p[0]
    return d
def pidof():
    p=sh('shell','pidof',PKG); return int(p.split()[0]) if p.strip() else None
COMP=sh('shell','cmd','package','resolve-activity','--brief','-c','android.intent.category.LAUNCHER',PKG).splitlines()[-1].strip()
before=md5s(); print('BEFORE md5 count=%d'%len(before))
sh('shell','am','force-stop',PKG); time.sleep(1.0)
dev=frida.get_usb_device(timeout=10)
sh('shell','am','start','-n',COMP)
pid=None; t0=time.time()
while time.time()-t0<15:
    pid=pidof()
    if pid: break
    time.sleep(0.10)
print('pid @%.2fs'%(time.time()-t0), pid)
if not pid: sys.exit('NO PID')
msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p); tag=p.get('tag')
        if tag=='WRITE':
            print('  << WRITE %s %s total=%s head=%s'%(p['kind'],(p.get('path') or '').split('/')[-1],p.get('total'),(p.get('head') or '')[:80]))
        elif tag=='RENAME': print('  << RENAME %s -> %s'%(p.get('old'),p.get('nw')))
        elif tag=='MSYNC': print('  << MSYNC len=%s head=%s'%(p.get('len'),(p.get('head') or '')[:64]))
        elif tag=='RDR': print('  << RDR %s len=%s head=%s'%((p.get('path') or '').split('/')[-1],p.get('len'),(p.get('head') or '')[:64]))
        elif tag=='EINIT': print('  << EINIT kb=%s key=%s iv=%s'%(p.get('kb'),p.get('key'),p.get('iv')))
        elif tag=='KEY': print('  << KEY kb=%s key=%s'%(p.get('kb'),p.get('key')))
        elif tag in ('READY','IOHOOK','WAIT_DLOPEN'): print('  <<',tag,p.get('base') or '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)
sess=None
for i in range(20):
    try: sess=dev.attach(pid); break
    except Exception:
        np=pidof()
        if np and np!=pid: pid=np
        time.sleep(0.20)
if not sess: sys.exit('ATTACH FAILED')
print('attached @%.2fs'%(time.time()-t0))
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
def nudge(): sh('shell','input','tap','540','1180'); sh('shell','input','swipe','540','1500','540','600','200')
last=0; didbg=False
while time.time()-t0<SECS:
    time.sleep(1.0)
    try: st=exp.status()
    except Exception as e: print('t%2.0f gone(%s)'%(time.time()-t0,type(e).__name__)); break
    el=time.time()-t0; print('t%2.0f %s'%(el,st))
    if el-last>=4: last=el; nudge()
    # lifecycle flush trigger around t18: HOME then resume
    if el>=18 and not didbg:
        didbg=True; print('  ** trigger HOME->resume (flush) **')
        sh('shell','input','keyevent','3'); time.sleep(2.5); sh('shell','monkey','-p',PKG,'-c','android.intent.category.LAUNCHER','1')
try: data=exp.dump()
except Exception as e: data={}; print('dump exc',e)
after=md5s()
changed=[k for k in after if before.get(k)!=after.get(k)]
newk=[k for k in after if k not in before]
print('=== CHANGED files during window: %s  NEW: %s ==='%(changed,newk))
json.dump({'pid':pid,'before':before,'after':after,'changed':changed,'msgs':msgs,'data':data},open(OUT,'w'),indent=1)
w=[m for m in msgs if m.get('tag')=='WRITE']; e=[m for m in msgs if m.get('tag')=='EINIT']; k=[m for m in msgs if m.get('tag')=='KEY']
print('=== WRITE=%d EINIT=%d KEY=%d ==='%(len(w),len(e),len(k)))
print('WROTE',OUT)
try: scr.unload()
except: pass
