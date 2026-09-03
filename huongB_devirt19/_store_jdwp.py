import frida, subprocess, sys, time, json, threading
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
ACT=PKG+'/com.ss.android.ugc.aweme.splash.SplashActivity'
JS='_store_oracle8c.js'
JPORT='55055'
DUR=float(sys.argv[1]) if len(sys.argv)>1 else 30.0
def sh(*a): return subprocess.run([ADB,*a],capture_output=True,text=True)

sh('shell','am','force-stop',PKG); time.sleep(0.3)
sh('shell','am','set-debug-app','-w','--persistent',PKG)
print('set-debug-app -w armed',flush=True)
dev=frida.get_usb_device(timeout=5)
sh('shell','am','start','-n',ACT)
t0=time.time(); pid=None
while time.time()-t0<12:
    r=subprocess.run([ADB,'shell','pidof','-s',PKG],capture_output=True,text=True)
    s=r.stdout.strip()
    if s.isdigit(): pid=int(s); break
    time.sleep(0.02)
if not pid: print('NO PID'); sh('shell','am','clear-debug-app'); sys.exit(1)
print('PID',pid,'(blocked at JDWP-wait) t=%.2f'%(time.time()-t0),flush=True)

sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
hits={}
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; tag=p.get('tag','?'); hits[tag]=hits.get(tag,0)+1
        print('EV',json.dumps(p),flush=True)
    else: print('ERRMSG',m,flush=True)
scr.on('message',on_msg); scr.load()
print('HOOKS INSTALLED (app still blocked). Releasing via jdb...',flush=True)

# forward jdwp + release with jdb
sh('forward','tcp:'+JPORT,'jdwp:'+str(pid))
jdb=subprocess.Popen(['/usr/bin/jdb','-connect',
    'com.sun.jdi.SocketAttach:hostname=localhost,port='+JPORT],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
def jdb_reader():
    for line in jdb.stdout:
        pass
threading.Thread(target=jdb_reader,daemon=True).start()
time.sleep(1.0)
try:
    jdb.stdin.write('cont\n'); jdb.stdin.flush()
except Exception as e: print('jdb write err',e,flush=True)
print('RELEASED, collecting %ss...'%DUR,flush=True)
time.sleep(DUR)

try:
    d=scr.exports_sync.dump()
    open('_store_jdwp_events.json','w').write(json.dumps(d,indent=1))
    evs=d.get('events',[]); print('TOTAL',len(evs),'installed=',d.get('installed'),flush=True)
    print('HITS',json.dumps(hits),flush=True)
    for e in evs:
        if e.get('t') in ('RDR','READ'):
            c=e.get('cipher') or ''
            print('  %s %s len=%s cipher=%s'%(e['t'],e.get('store'),e.get('len',e.get('n')),c[:80]),flush=True)
        if e.get('t')=='EINIT' and e.get('win'):
            print('  EINIT-WIN store=%s key=%s iv=%s'%(e.get('store'),e.get('key'),e.get('iv')),flush=True)
        if e.get('t') in ('BDEC','BENC','CBCD','CBCE'):
            print('  %s store=%s in=%s out=%s'%(e['t'],e.get('store'),e.get('in16'),e.get('out16')),flush=True)
except Exception as ex: print('dump exc',ex,flush=True)

try: jdb.stdin.write('quit\n'); jdb.stdin.flush()
except: pass
sh('shell','am','clear-debug-app')
sess.detach()
print('DONE (clear-debug-app restored)',flush=True)
