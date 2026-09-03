import frida, subprocess, sys, time, json, socket
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
ACT=PKG+'/com.ss.android.ugc.aweme.splash.SplashActivity'
JS='_oracle_open.js'; JPORT=55078
DUR=float(sys.argv[1]) if len(sys.argv)>1 else 8.0
def sh(*a): return subprocess.run([ADB,*a],capture_output=True,text=True)
def log(*a): print(*a,flush=True)
sh('shell','am','force-stop',PKG); time.sleep(0.3)
sh('shell','am','set-debug-app','-w','--persistent',PKG)
dev=frida.get_usb_device(timeout=5)
sh('shell','am','start','-n',ACT)
t0=time.time(); pid=None
while time.time()-t0<12:
    r=subprocess.run([ADB,'shell','pidof','-s',PKG],capture_output=True,text=True); s=r.stdout.strip()
    if s.isdigit(): pid=int(s);break
    time.sleep(0.02)
if not pid: log('NO PID'); sh('shell','am','clear-debug-app'); sys.exit(1)
log('PID',pid,'blocked t=%.2f'%(time.time()-t0))
sess=dev.attach(pid); scr=sess.create_script(open(JS).read())
evs=[]
def onmsg(m,d):
    p=m.get('payload',m)
    if isinstance(p,dict) and p.get('tag') in ('SOPEN','SREAD'): log('*** '+json.dumps(p))
    evs.append(p)
scr.on('message',onmsg); scr.load()
log('HOOKS IN. forward+handshake release...')
sh('forward','tcp:%d'%JPORT,'jdwp:%d'%pid)
try:
    js=socket.create_connection(('localhost',JPORT),timeout=5); js.settimeout(5)
    js.sendall(b'JDWP-Handshake')
    hs=b''
    try:
        while len(hs)<14: c=js.recv(14-len(hs));
        # note: recv loop below
    except Exception: pass
    # simpler: single recv
except Exception as e:
    log('handshake err',e); js=None
# robust single-recv handshake
try:
    hs=js.recv(64) if js else b''
    log('handshake resp=%r'%hs)
except Exception as e:
    log('recv err',e)
log('collecting %ss...'%DUR); time.sleep(DUR)
sopen=[e for e in evs if isinstance(e,dict) and e.get('tag')=='SOPEN']
sread=[e for e in evs if isinstance(e,dict) and e.get('tag')=='SREAD']
allop=[e for e in evs if isinstance(e,dict) and e.get('tag')=='OPEN']
log('SUMMARY sopen=%d sread=%d otheropen=%d'%(len(sopen),len(sread),len(allop)))
try: log('STATS',scr.exports_sync.stats())
except Exception as e: log('stats exc',e)
json.dump({'sopen':sopen,'sread':sread,'nopen':len(allop),
           'sample_open':[e.get('path') for e in allop[:40]]}, open('_openscan.json','w'), indent=1)
try: js.close()
except: pass
sh('shell','am','clear-debug-app')
try: sess.detach()
except: pass
log('DONE')
