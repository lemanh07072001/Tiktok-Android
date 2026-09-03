import sys,time,json,subprocess,os
import frida
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
JS='_store_load.js'
OUT='cap.noindex/store_load.json'
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
sh('shell','am','force-stop',PKG); time.sleep(1.2)
dev=frida.get_usb_device(timeout=10)
sh('shell','am','start','-n',COMP)
# relaxed pid wait — libmetasec loads later, no millisecond race
pid=None; t0=time.time()
while time.time()-t0<15:
    pid=pidof()
    if pid: break
    time.sleep(0.25)
print('pid @%.2fs'%(time.time()-t0), pid)
if not pid: print('NO PID'); sys.exit(1)
print('lib at attach-time?', lib_loaded(pid))

msgs=[]
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p)
        tag=p.get('tag')
        if tag=='KEY': print('  << KEY kb=%s %s'%(p.get('kb'),p.get('key')))
        elif tag=='EINIT': print('  << EINIT kb=%s key=%s iv=%s'%(p.get('kb'),p.get('key'),p.get('iv')))
        elif tag=='CT':
            e=p['ev']; print('  << CT %s key=%s iv=%s len=%s in=%s'%(e['prim'],(e['key'] or '')[:16],(e['iv'] or ''),e['len'],(e['inhex'] or '')[:32]))
        else: print('  <<',tag,p.get('base') or '', 'preloaded=%s'%p.get('preloaded') if tag=='READY' else '')
    else: msgs.append({'tag':'ERR','m':str(m)}); print('  << ERR',m)

sess=None
for i in range(15):
    try: sess=dev.attach(pid); break
    except Exception as e:
        np=pidof()
        if np and np!=pid: pid=np
        time.sleep(0.4)
if not sess: print('ATTACH FAILED'); sys.exit(1)
print('attached @%.2fs pid %d'%(time.time()-t0,pid))
scr=sess.create_script(open(JS).read()); scr.on('message',on_msg); scr.load()
exp=getattr(scr,'exports_sync',None) or scr.exports
print('oracle live @%.2fs'%(time.time()-t0))

def nudge():
    # push past splash into feed to trigger first signed request -> libmetasec load
    sh('shell','input','tap','540','1180')
    sh('shell','input','swipe','540','1500','540','600','200')

tt=time.time(); loaded=False; loaded_at=None; last_nudge=0
while time.time()-tt<SECS:
    time.sleep(1.0)
    try: st=exp.status()
    except Exception as e:
        print('t%2.0f script gone (%s) — streamed data already safe'%(time.time()-tt,type(e).__name__)); break
    el=time.time()-tt
    if not loaded and (st.get('installed') or lib_loaded(pid)):
        loaded=True; loaded_at=el; print('t%2.0f *** libmetasec LOADED, hooks installed=%s'%(el,st.get('installed')))
    print('t%2.0f status %s'%(el,st))
    # nudge every 4s until lib loads
    if not loaded and el-last_nudge>=4:
        last_nudge=el; nudge(); print('t%2.0f nudge (tap+swipe)'%el)
    # once we have EINIT or CT, collect a short tail then pull store
    if st.get('neinit',0)>0 or st.get('ncts',0)>0:
        if el>(loaded_at or 0)+6:
            print('t%2.0f captured einit/ct, ending collection'%el); break

# snapshot fresh store from THIS session
snap='cap.noindex/store_snap_%d'%int(time.time())
sh('shell','su','0','sh','-c','mkdir -p /data/local/tmp/ovsnap && cp -a %s/. /data/local/tmp/ovsnap/ 2>/dev/null; chmod -R 777 /data/local/tmp/ovsnap'%STOREDIR)
os.makedirs(snap,exist_ok=True)
sh('pull','/data/local/tmp/ovsnap','%s/'%snap)
print('store snapshot ->',snap)

try: data=exp.dump()
except Exception as e: print('dump exc',repr(e)); data={}
streamed={'KEY':[m for m in msgs if m.get('tag')=='KEY'],
          'EINIT':[m for m in msgs if m.get('tag')=='EINIT'],
          'CT':[m['ev'] for m in msgs if m.get('tag')=='CT']}
json.dump({'pid':pid,'loaded_at':loaded_at,'snap':snap,'msgs':msgs,'data':data,'streamed':streamed}, open(OUT,'w'), indent=1)
print('=== SUMMARY: KEY=%d EINIT=%d CT=%d ==='%(len(streamed['KEY']),len(streamed['EINIT']),len(streamed['CT'])))
for m in streamed['EINIT']: print('   EINIT kb=%s key=%s iv=%s'%(m.get('kb'),m.get('key'),m.get('iv')))
for m in streamed['KEY']: print('   KEY kb=%s %s'%(m.get('kb'),m.get('key')))
print('WROTE',OUT)
try: scr.unload()
except: pass
try: sess.detach()
except: pass
print('DONE — no re-register')
