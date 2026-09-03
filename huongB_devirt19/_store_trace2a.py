import sys,time,json,subprocess,os
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'; JS='_store_trace2.js'; OUT='cap.noindex/store_trace2a.json'
STOREDIR='/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 35
os.makedirs('cap.noindex',exist_ok=True)
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pidof():
    p=sh('shell','pidof',PKG); return int(p.split()[0]) if p.strip() else None
COMP=sh('shell','cmd','package','resolve-activity','--brief','-c','android.intent.category.LAUNCHER',PKG).splitlines()[-1].strip()
sh('shell','am','force-stop',PKG); time.sleep(1.0)
dev=frida.get_usb_device(timeout=10)
sh('shell','am','start','-n',COMP)
pid=None; t0=time.time()
while time.time()-t0<15:
    pid=pidof()
    if pid: break
    time.sleep(0.15)
print('pid @%.2fs'%(time.time()-t0), pid)
if not pid: sys.exit('NO PID')
msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p); tag=p.get('tag')
        if tag in ('FILERD','FILEWR','FILEMMAP'): print('  << %s %s sz=%s head=%s'%(tag,(p.get('path') or '').split('/')[-1],p.get('ret'),(p.get('head') or '')[:64]))
        elif tag=='RDR': print('  << RDR %s len=%s head=%s'%((p.get('path') or '').split('/')[-1],p.get('len'),(p.get('head') or '')[:64]))
        elif tag in ('READY','FILEHOOK','WAIT_DLOPEN'): print('  <<',tag,p.get('base') or '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)
sess=None
for i in range(20):
    try: sess=dev.attach(pid); break
    except Exception:
        np=pidof();
        if np and np!=pid: pid=np
        time.sleep(0.25)
if not sess: sys.exit('ATTACH FAILED')
print('attached @%.2fs'%(time.time()-t0))
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
def nudge(): sh('shell','input','tap','540','1180'); sh('shell','input','swipe','540','1500','540','600','200')
last=0
while time.time()-t0<SECS:
    time.sleep(1.0)
    try: st=exp.status()
    except Exception as e: print('t%2.0f gone(%s)'%(time.time()-t0,type(e).__name__)); break
    el=time.time()-t0; print('t%2.0f %s'%(el,st))
    if el-last>=4: last=el; nudge()
try: data=exp.dump()
except Exception as e: data={}; print('dump exc',e)
json.dump({'pid':pid,'msgs':msgs,'data':data},open(OUT,'w'),indent=1)
fr=[m for m in msgs if m.get('tag') in ('FILERD','FILEWR','FILEMMAP','RDR')]
print('=== FILE/RDR/MMAP events=%d ==='%len(fr))
seen=set()
for m in fr:
    k=(m.get('tag'),m.get('path'))
    if k in seen: continue
    seen.add(k); print('   %s %s sz=%s head=%s'%(m.get('tag'),(m.get('path') or '').split('/')[-1],m.get('ret') or m.get('len'),(m.get('head') or '')[:80]))
print('WROTE',OUT)
try: scr.unload()
except: pass
