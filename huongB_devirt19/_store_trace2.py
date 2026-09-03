import sys,time,json,subprocess,os
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_store_trace2.js'
OUT='cap.noindex/store_trace2.json'
STOREDIR='/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 50
os.makedirs('cap.noindex',exist_ok=True)
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pidof():
    p=sh('shell','pidof',PKG); return int(p.split()[0]) if p.strip() else None

sh('shell','am','force-stop',PKG); time.sleep(1.0)
dev=frida.get_usb_device(timeout=10)
print('SPAWNING (suspended) — hooks install before any init I/O ...')
pid=dev.spawn([PKG])
print('spawned pid',pid)
msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p); tag=p.get('tag')
        if tag in ('FILERD','FILEWR'): print('  << %s %s ret=%s head=%s'%(tag,p.get('path'),p.get('ret'),(p.get('head') or '')[:64]))
        elif tag=='RDR': print('  << RDR path=%s len=%s head=%s'%(p.get('path'),p.get('len'),(p.get('head') or '')[:64]))
        elif tag=='KEY': print('  << KEY kb=%s %s'%(p.get('kb'),p.get('key')))
        elif tag=='EINIT': print('  << EINIT kb=%s key=%s iv=%s'%(p.get('kb'),p.get('key'),p.get('iv')))
        elif tag in ('READY','FILEHOOK','WAIT_DLOPEN','FILEHOOK_ERR'): print('  <<',tag,p.get('base') or '', p.get('e') or '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)

sess=dev.attach(pid)
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
dev.resume(pid); print('resumed @0.00s')
t0=time.time()

def nudge():
    sh('shell','input','tap','540','1180'); sh('shell','input','swipe','540','1500','540','600','200')

last_nudge=0
while time.time()-t0<SECS:
    time.sleep(1.0)
    try: st=exp.status()
    except Exception as e: print('t%2.0f script gone (%s)'%(time.time()-t0,type(e).__name__)); break
    el=time.time()-t0
    print('t%2.0f status %s'%(el,st))
    if el>6 and el-last_nudge>=4: last_nudge=el; nudge(); print('t%2.0f nudge'%el)

snap='cap.noindex/store_trace2_pull_%d'%int(time.time())
sh('shell','su','0','sh','-c','rm -rf /data/local/tmp/ovt2; mkdir -p /data/local/tmp/ovt2 && cp -a %s/. /data/local/tmp/ovt2/ 2>/dev/null; chmod -R 777 /data/local/tmp/ovt2'%STOREDIR)
os.makedirs(snap,exist_ok=True); sh('pull','/data/local/tmp/ovt2','%s/'%snap)
try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
# merge streamed (survives script death) with dump
fr=[m for m in msgs if m.get('tag') in ('FILERD','FILEWR','RDR')]
json.dump({'pid':pid,'snap':snap,'msgs':msgs,'data':data}, open(OUT,'w'), indent=1)
print('=== SUMMARY streamed: FILE/RDR=%d EINIT=%d KEY=%d ==='%(
   len(fr), len([m for m in msgs if m.get('tag')=='EINIT']), len([m for m in msgs if m.get('tag')=='KEY'])))
seen=set()
for m in fr:
    k=(m.get('tag'),m.get('path'),m.get('ret') or m.get('len'))
    if k in seen: continue
    seen.add(k)
    print('   %s %s sz=%s head=%s'%(m.get('tag'),(m.get('path') or '').split('/')[-1],m.get('ret') or m.get('len'),(m.get('head') or '')[:64]))
print('WROTE',OUT)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — spawn+read, no re-register')
