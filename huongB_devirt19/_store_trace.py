import sys,time,json,subprocess,os
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_store_trace.js'
OUT='cap.noindex/store_trace.json'
STOREDIR='/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 60
os.makedirs('cap.noindex',exist_ok=True)
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pidof():
    p=sh('shell','pidof',PKG); return int(p.split()[0]) if p.strip() else None
def lib_loaded(pid):
    r=sh('shell','su','0','sh','-c',"grep -c libmetasec_ov /proc/%d/maps 2>/dev/null"%pid)
    try: return int(r.strip() or '0')>0
    except: return False

COMP=sh('shell','cmd','package','resolve-activity','--brief','-c','android.intent.category.LAUNCHER',PKG).splitlines()[-1].strip()
print('COMP',COMP)
# force-stop is SANCTIONED (keeps /data login+store) -> relaunch so we attach at splash
# and catch the store file open()/read() from the start.
sh('shell','am','force-stop',PKG); time.sleep(1.2)
dev=frida.get_usb_device(timeout=10)
sh('shell','am','start','-n',COMP)
pid=None; t0=time.time()
while time.time()-t0<15:
    pid=pidof()
    if pid: break
    time.sleep(0.2)
print('pid @%.2fs'%(time.time()-t0), pid)
if not pid: print('NO PID'); sys.exit(1)

msgs=[]; nfile=0
def on_msg(m,d):
    global nfile
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p); tag=p.get('tag')
        if tag=='FILERD':
            nfile+=1; print('  << FILERD %s ret=%s head=%s'%(p.get('path'),p.get('ret'),(p.get('head') or '')[:48]))
        elif tag=='KEY': print('  << KEY kb=%s %s'%(p.get('kb'),p.get('key')))
        elif tag=='EINIT': print('  << EINIT kb=%s key=%s iv=%s'%(p.get('kb'),p.get('key'),p.get('iv')))
        elif tag=='CT':
            e=p['ev']; print('  << CT %s key=%s iv=%s len=%s'%(e['prim'],(e['key'] or '')[:16],(e['iv'] or ''),e['len']))
        elif tag in ('READY','FILEHOOK','WAIT_DLOPEN','FILEHOOK_ERR'):
            print('  <<',tag,p.get('base') or '', p.get('e') or '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)

sess=None
for i in range(20):
    try: sess=dev.attach(pid); break
    except Exception as e:
        np=pidof()
        if np and np!=pid: pid=np
        time.sleep(0.3)
if not sess: print('ATTACH FAILED'); sys.exit(1)
print('attached @%.2fs pid %d'%(time.time()-t0,pid))
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
print('trace oracle live @%.2fs'%(time.time()-t0))

def nudge():
    sh('shell','input','tap','540','1180')
    sh('shell','input','swipe','540','1500','540','600','200')

tt=time.time(); loaded=False; loaded_at=None; last_nudge=0
while time.time()-tt<SECS:
    time.sleep(1.0)
    try: st=exp.status()
    except Exception as e:
        print('t%2.0f script gone (%s)'%(time.time()-tt,type(e).__name__)); break
    el=time.time()-tt
    if not loaded and (st.get('installed') or lib_loaded(pid)):
        loaded=True; loaded_at=el; print('t%2.0f *** libmetasec LOADED installed=%s'%(el,st.get('installed')))
    print('t%2.0f status %s'%(el,st))
    if el-last_nudge>=4:
        last_nudge=el; nudge(); print('t%2.0f nudge'%el)

# pull the LIVE store from THIS same session (correlates with captured file reads)
snap='cap.noindex/store_trace_pull_%d'%int(time.time())
sh('shell','su','0','sh','-c','rm -rf /data/local/tmp/ovtr; mkdir -p /data/local/tmp/ovtr && cp -a %s/. /data/local/tmp/ovtr/ 2>/dev/null; chmod -R 777 /data/local/tmp/ovtr'%STOREDIR)
os.makedirs(snap,exist_ok=True)
sh('pull','/data/local/tmp/ovtr','%s/'%snap)
print('store pull ->',snap)

try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
json.dump({'pid':pid,'loaded_at':loaded_at,'snap':snap,'msgs':msgs,'data':data}, open(OUT,'w'), indent=1)
fr=data.get('filerd',[]) if isinstance(data,dict) else []
ei=data.get('einits',{}) if isinstance(data,dict) else {}
ky=data.get('keys',{}) if isinstance(data,dict) else {}
print('=== SUMMARY: FILERD=%d KEYS=%d EINIT=%d CT=%d ==='%(len(fr),len(ky),len(ei),len(data.get('cts',[]) if isinstance(data,dict) else [])))
for f in fr: print('   FILE %s ret=%s head=%s'%(f['path'].split('/')[-1],f['ret'],(f['bytes'] or '')[:48]))
for k in ei: print('   EINIT',k)
for k in ky: print('   KEY',k)
print('WROTE',OUT)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — no re-register')
