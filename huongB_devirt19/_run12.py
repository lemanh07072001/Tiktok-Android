#!/usr/bin/env python3
import sys, json, time, frida
PACKAGE='com.zhiliaoapp.musically'
JS=sys.argv[1]; TIMEOUT=int(sys.argv[2]) if len(sys.argv)>2 else 60
OUT=JS.replace('.js','.out.json')
js=open(JS).read()
print(f"[*] spawning {PACKAGE}")
dev=frida.get_usb_device()
pid=dev.spawn([PACKAGE]); ses=dev.attach(pid); scr=ses.create_script(js)
done={'v':False}
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t','')
        if t=='info': print(f"[info] {p.get('msg')}  base={p.get('base')}")
        elif t=='ready': print("[*] hooks installed — waiting…")
        elif t=='mon': print(f"  [mon] calls={p['calls']} disp={p['disp']} dumped={p['dumped']}")
        elif t=='BT': print(f"[BT] firstCall={p['callId']} bt={[hex(x) if x>=0 else x for x in p['bt']]}")
        elif t=='SM3':
            print(f"\n[SM3] slot16={p['slot16']} buf={p['buf']} lr={hex(p['lr']) if p['lr']>=0 else p['lr']} nCalls={p['nCalls']}")
            print(f"  bufNbr(-32..+64)={p['bufNbr']}")
            print(f"  #calls kept={len(p['calls'])}")
            for c in p['calls']:
                tg = hex(c['tgt']) if c['tgt']>=0 else c['tgt']
                print(f"    call#{c['id']} tgt={tg} disp={c['disp']} ctx={c['ctx']} inp={c['inp']}")
            json.dump(p, open(OUT,'w'), indent=1)
            print(f"\n[*] saved {OUT}")
            done['v']=True
        elif t=='error': print(f"[ERR] {p}")
        else: print(f"[msg] {p}")
    elif m.get('type')=='error':
        print(f"[JS ERR] {m.get('description')}")
        if 'stack' in m: print(m['stack'])
scr.on('message', on_msg); scr.load(); dev.resume(pid)
print(f"[*] up to {TIMEOUT}s…")
dl=time.time()+TIMEOUT
while time.time()<dl and not done['v']: time.sleep(0.4)
try: ses.detach()
except: pass
print(f"[*] detached. done={done['v']}")
