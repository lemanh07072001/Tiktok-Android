import frida, subprocess, sys, time, json
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
ACT=PKG+'/com.ss.android.ugc.aweme.splash.SplashActivity'
JS='_store_oracle8b.js'
DUR=float(sys.argv[1]) if len(sys.argv)>1 else 35.0

def sh(*a): return subprocess.run([ADB,'shell',*a],capture_output=True,text=True)

print('force-stop...',flush=True); sh('am','force-stop',PKG); time.sleep(0.4)
dev=frida.get_usb_device(timeout=5)
print('am start...',flush=True)
sh('am','start','-n',ACT)
t0=time.time(); pid=None
# tight pidof poll
while time.time()-t0 < 8:
    r=subprocess.run([ADB,'shell','pidof','-s',PKG],capture_output=True,text=True)
    s=r.stdout.strip()
    if s.isdigit(): pid=int(s); break
    time.sleep(0.015)
if not pid: print('NO PID',flush=True); sys.exit(1)
lat=time.time()-t0
print('PID',pid,'attach-latency %.3fs'%lat,flush=True)
sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
hits={'RDR':0,'READ':0,'OPEN':0,'BENC':0,'BDEC':0,'CBCE':0,'CBCD':0,'DISP':0,'EINIT':0}
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; tag=p.get('tag','?')
        hits[tag]=hits.get(tag,0)+1
        print('EV',json.dumps(p),flush=True)
    else:
        print('ERRMSG',m,flush=True)
scr.on('message',on_msg)
scr.load()
print('LOADED at %.3fs, collecting %ss...'%(time.time()-t0,DUR),flush=True)
time.sleep(DUR)
try:
    d=scr.exports_sync.dump()
    open('_store_race2_events.json','w').write(json.dumps(d,indent=1))
    evs=d.get('events',[])
    print('TOTAL events:',len(evs),flush=True)
    print('HITS',json.dumps(hits),flush=True)
    # summarize RDR/READ ciphertext
    for e in evs:
        if e.get('t') in ('RDR','READ'):
            c=e.get('cipher') or ''
            print('  %s %s len=%s cipher[:64]=%s'%(e['t'],e.get('store'),e.get('len',e.get('n')),c[:64]),flush=True)
        if e.get('t')=='EINIT' and e.get('win'):
            print('  EINIT-WIN store=%s kb=%s key=%s iv=%s'%(e.get('store'),e.get('kb'),e.get('key'),e.get('iv')),flush=True)
except Exception as ex:
    print('dump exc',ex,flush=True)
sess.detach()
print('DONE',flush=True)
