#!/usr/bin/env python3
# SPAWN oracle driver — removes attach-timing race for a crash-looping app.
# frida spawns TikTok suspended, loads the RDR/KSCH/EINIT oracle, resumes.
# Hooks are guaranteed installed before app code runs; init-time store read
# (.msp/.mss/.msf3) streams out via send() instantly, before the app can die
# or finish any anti-frida check. ATTACH/SPAWN only — NO re-register (login persists).
import sys, time, json, threading, subprocess
import frida

PKG='com.zhiliaoapp.musically'
JS='_store_key_grab2.js'
OUT='_grab_spawn_out.json'
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 30

events=[]
lock=threading.Lock()
def on_msg(m,data):
    if m.get('type')=='send':
        p=m.get('payload',{})
        with lock: events.append(p)
        t=p.get('tag')
        if t=='READY': print('  [READY] base=%s'%p.get('base'))
        elif t=='RDR': print('  [RDR ] store=%s len=%s head=%s'%(p.get('store'),p.get('len'),p.get('head')))
        elif t=='KSCH': print('  [KSCH] win=%s keyBytes=%s userKey=%s'%(p.get('win'),p.get('kb'),p.get('uk')))
        elif t=='EINIT':print('  [EINIT] win=%s kb=%s uk=%s iv=%s'%(p.get('win'),p.get('keyBytes'),p.get('userKey'),p.get('iv')))
        else: print('  [%s] %s'%(t,{k:v for k,v in p.items() if k!='tag'}))
    elif m.get('type')=='error':
        print('  [JS-ERR]', m.get('stack') or m.get('description'))

def get_device():
    for _ in range(6):
        try: return frida.get_usb_device(timeout=5)
        except Exception as e:
            print('  get_usb_device retry:', e); time.sleep(2)
    raise SystemExit('no usb device')

def main():
    dev=get_device()
    print('device:', dev.id)
    code=open(JS).read()
    print('spawning %s ...'%PKG)
    try:
        pid=dev.spawn([PKG])
    except Exception as e:
        print('SPAWN FAILED:', e)
        print('  -> host too loaded / zygote wedged. See blocked handoff.')
        raise SystemExit(2)
    print('spawned pid=%d (suspended)'%pid)
    try:
        sess=dev.attach(pid)
        scr=sess.create_script(code)
        scr.on('message', on_msg)
        scr.load()
        print('script loaded; resuming...')
        dev.resume(pid)
    except Exception as e:
        print('ATTACH/LOAD FAILED:', e)
        try: dev.kill(pid)
        except Exception: pass
        raise SystemExit(3)

    # drive a couple of feed swipes mid-window in case store writes on interaction
    def drive():
        time.sleep(8)
        for i in range(3):
            try: subprocess.run([ADB,'shell','input','swipe','540','1500','540','400','120'],timeout=8)
            except Exception: pass
            time.sleep(3)
    threading.Thread(target=drive,daemon=True).start()

    def snapshot(reason):
        try:
            full=scr.exports_sync.dump()
        except Exception as e:
            return None
        with lock:
            merged={'stream':list(events),'dump':full}
        json.dump(merged,open(OUT,'w'),indent=1)
        keyed=[e for e in full if e.get('win') and e.get('userKey') and e.get('keyBytes') in (16,24,32)]
        if keyed:
            print('  >> [%s] dump has KEY material (%d) -> persisted %s'%(reason,len(keyed),OUT))
        return full

    t0=time.time(); got_key=False
    while time.time()-t0 < SECS:
        time.sleep(1)
        full=snapshot('poll')          # persist every second (survives sudden death)
        if full:
            if any(e.get('win') and e.get('userKey') and e.get('keyBytes') in (16,24,32) for e in full):
                got_key=True
                print('  >> key captured; holding 3s for IV/ciphertext stragglers'); time.sleep(3)
                snapshot('final'); break

    try: print('status:',scr.exports_sync.status())
    except Exception as e: print('status err:',e)
    full=snapshot('end') or []

    # summary (from dump — key bytes live there, not in the stream)
    rdr=[e for e in full if e.get('t')=='RDR']
    ksch=[e for e in full if e.get('t')=='KSCH']
    ein=[e for e in full if e.get('t')=='EINIT']
    blk=[e for e in full if e.get('t') in ('BENC','BDEC','CBCE','CBCD')]
    print('\n=== SUMMARY (dump) ===')
    print('RDR:%d KSCH:%d EINIT:%d BLK:%d'%(len(rdr),len(ksch),len(ein),len(blk)))
    for e in rdr:
        print('  RDR store=%s len=%s cipher=%s'%(e.get('store'),e.get('len'),(e.get('cipher') or '')[:64]))
    for e in ksch+ein:
        print('  %s win=%s store=%s keyBytes=%s userKey=%s iv=%s'%(e.get('t'),e.get('win'),e.get('store'),e.get('keyBytes'),e.get('userKey'),e.get('iv')))
    if not (ksch or ein):
        print('  (no key schedule fired — store may use a custom PRG, not the AES module)')

    try: scr.unload()
    except Exception: pass

if __name__=='__main__':
    main()
