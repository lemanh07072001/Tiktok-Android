#!/usr/bin/env python3
# WAIT-FOR-DEBUGGER capture — load-immune alternative to frida's gated spawn.
# 1) am set-debug-app -w + am start -> app forks and PARKS at the JDWP debugger
#    wait, BEFORE Application init (before libmetasec loads / reads the store).
#    Parking is passive (thread sleeps) so it reaches the gate under ANY host load.
# 2) attach frida to the parked pid, load dlopen-early oracle (libmetasec not yet
#    mapped -> the dlopen hook WILL catch its load, install RDR/KSCH pre-init-read).
# 3) release the JDWP wait with jdb -> app runs init -> store read fires IN-WINDOW.
# ATTACH ONLY. NO re-register (device_id+login persist on /data).
import sys, time, json, threading, subprocess, re, socket, struct
import frida

PKG='com.zhiliaoapp.musically'
COMP='com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity'
JS='_store_io_probe.js'
OUT='cap.noindex/io_probe_out.json'          # .noindex dir: Spotlight ignores it
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
JDB='/usr/bin/jdb'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 45

def sh(*a, t=15):
    return subprocess.run([ADB,'shell',*a],capture_output=True,text=True,timeout=t).stdout.strip()

events=[]; lock=threading.Lock()
def on_msg(m,data):
    if m.get('type')=='send':
        p=m.get('payload',{})
        with lock: events.append(p)
        t=p.get('tag')
        if t=='BOOT': print('  [BOOT]',p.get('msg'))
        elif t=='READY': print('  [READY] base=%s'%p.get('base'))
        elif t=='RDR': print('  [RDR ] store=%s path=%s len=%s'%(p.get('store'),p.get('path'),p.get('len')))
        elif t=='KSCH': print('  [KSCH] win=%s keyBytes=%s'%(p.get('win'),p.get('keyBytes')))
        elif t=='EINIT':print('  [EINIT] win=%s keyBytes=%s'%(p.get('win'),p.get('keyBytes')))
        else: print('  [%s] %s'%(t,{k:v for k,v in p.items() if k!='tag'}))
    elif m.get('type')=='error':
        print('  [JS-ERR]', m.get('stack') or m.get('description'))

def wait_pid(timeout=25):
    t0=time.time()
    while time.time()-t0<timeout:
        p=sh('pidof',PKG,t=8)
        if p.strip(): return int(p.split()[0])
        time.sleep(0.3)
    return None

def release_debugger(pid, secs):
    # Raw-JDWP release: frida is ptrace (not JDWP) so it never completes the
    # Debug.waitForDebugger() handshake. Do it in pure Python, send VM.Resume
    # (cmdset 1, cmd 9) because ART leaves the VM suspend-on-start, then HOLD the
    # socket open + drain events for the whole capture so ART never re-parks.
    port='8700'
    subprocess.run([ADB,'forward','tcp:'+port,'jdwp:%d'%pid],capture_output=True,text=True,timeout=10)
    time.sleep(0.3)
    s=None
    try:
        s=socket.create_connection(('localhost',int(port)),timeout=10)
        s.sendall(b'JDWP-Handshake')
        hs=b''
        while len(hs)<14:
            c=s.recv(14-len(hs))
            if not c: break
            hs+=c
        ok=(hs==b'JDWP-Handshake')
        # VM.Resume: len=11,id=1,flags=0,cmdset=1,cmd=9
        s.sendall(struct.pack('>IIBBB',11,1,0,1,9))
        print('  [jdwp] handshake=%s resume sent, holding %ds'%(ok,secs))
        s.settimeout(1.0)
        t0=time.time()
        while time.time()-t0<secs:
            try:
                d=s.recv(4096)          # drain composite events so ART is not blocked
                if not d: break
            except socket.timeout:
                pass
            except Exception:
                break
    except Exception as e:
        print('  [jdwp] err:',type(e).__name__,e)
    finally:
        try:
            if s: s.close()
        except Exception: pass
        subprocess.run([ADB,'forward','--remove','tcp:'+port],capture_output=True,text=True)

def main():
    # clean slate
    sh('am','force-stop',PKG,t=15); time.sleep(1)
    print('set-debug-app -w + start (park at debugger wait)...')
    sh('am','set-debug-app','-w','--persistent',PKG,t=10)
    subprocess.run([ADB,'shell','am','start','-n',COMP],capture_output=True,text=True,timeout=15)
    pid=wait_pid()
    if not pid:
        print('PARK FAILED: process never appeared'); raise SystemExit(2)
    print('parked pid=%d'%pid)

    dev=frida.get_usb_device(timeout=10)
    # warm up flaky transport, then retry attach+load (parked proc waits patiently)
    code=open(JS).read(); scr=None
    for att in range(8):
        try:
            try: dev.enumerate_processes()   # warm-up round-trip
            except Exception: pass
            sess=dev.attach(pid)
            scr=sess.create_script(code)
            scr.on('message', on_msg)
            scr.load()
            print('oracle loaded on parked process (attach attempt %d)'%att); break
        except Exception as e:
            print('  attach retry %d: %s'%(att, type(e).__name__)); time.sleep(3)
    if scr is None:
        print('ATTACH FAILED after retries'); 
        subprocess.run([ADB,'shell','am','clear-debug-app'],capture_output=True)
        subprocess.run([ADB,'shell','am','force-stop',PKG],capture_output=True)
        raise SystemExit(3)
    print('releasing debugger...')

    # release AFTER hooks are in place -> init runs with hooks live
    threading.Thread(target=release_debugger,args=(pid,SECS+5),daemon=True).start()
    # drive feed swipes late, in case store writes on interaction
    def drive():
        time.sleep(12)
        for _ in range(3):
            subprocess.run([ADB,'shell','input','swipe','540','1500','540','400','120'],capture_output=True,timeout=8)
            time.sleep(3)
    threading.Thread(target=drive,daemon=True).start()

    def snapshot(reason):
        try: full=scr.exports_sync.dump()
        except Exception: return None
        with lock: merged={'stream':list(events),'dump':full}
        json.dump(merged,open(OUT,'w'),indent=1)
        return full

    t0=time.time()
    while time.time()-t0<SECS:
        time.sleep(1)
        full=snapshot('poll')
        if full and any(e.get('win') and e.get('userKey') and e.get('keyBytes') in (16,24,32) for e in full):
            print('  >> IN-WINDOW store key captured; holding 3s for IV/ct'); time.sleep(3)
            snapshot('final'); break

    full=snapshot('end') or []
    try:
        mt=scr.exports_sync.meta()
        print('  META installed=%s events=%s'%(mt.get('installed'),mt.get('events')))
        print('  RDR paths sampled:'); [print('    R',p) for p in mt.get('rdrPaths',[])[:20]]
        print('  OPEN paths sampled:'); [print('    O',p) for p in mt.get('openPaths',[])[:20]]
    except Exception as e: print('meta err',e)
    # cleanup debug-app so future launches are normal
    sh('am','clear-debug-app',t=8)

    rdr=[e for e in full if e.get('t')=='RDR']
    ksch=[e for e in full if e.get('t')=='KSCH']
    ein=[e for e in full if e.get('t')=='EINIT']
    blk=[e for e in full if e.get('t') in ('BENC','BDEC','CBCE','CBCD')]
    print('\n=== SUMMARY (dump) ===')
    print('RDR:%d KSCH:%d EINIT:%d BLK:%d'%(len(rdr),len(ksch),len(ein),len(blk)))
    for e in rdr: print('  RDR store=%s path=%s len=%s cipher=%s'%(e.get('store'),e.get('path'),e.get('len'),(e.get('cipher') or '')[:48]))
    inwin=[e for e in ksch+ein if e.get('win')]
    print('IN-WINDOW key events: %d'%len(inwin))
    for e in inwin: print('  %s store=%s keyBytes=%s userKey=%s iv=%s'%(e.get('t'),e.get('store'),e.get('keyBytes'),e.get('userKey'),e.get('iv')))
    for e in blk: print('  %s store=%s in16=%s out16=%s'%(e.get('t'),e.get('store'),e.get('in16'),e.get('out16')))
    try: scr.unload()
    except Exception: pass

if __name__=='__main__': main()
