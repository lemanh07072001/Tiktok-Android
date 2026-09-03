#!/usr/bin/env python3
"""Spawn musically, run offset probe over natural init-burst, collect HITs (no clobber)."""
import sys,json,time,frida
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1] if len(sys.argv)>1 else '_p_offset_probe.js'
SECS=int(sys.argv[2]) if len(sys.argv)>2 else 45
OUT=JS.replace('.js','.out.jsonl')
code=open(JS).read()
dev=frida.get_usb_device()
pid=dev.spawn([PKG]); print(f"[*] spawned pid={pid}")
sess=dev.attach(pid); sc=sess.create_script(code)
fh=open(OUT,'w'); hits=[0]
def on_msg(m,d):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t','')
        if t=='info': print('[i]',p.get('msg'))
        elif t=='ready': print('[*] hooks ready')
        elif t=='mon': print(f"  [mon] ring={p['ring']} trig={p['trig']} nAll={p.get('nAll')} nSelf={p.get('nSelf')}")
        elif t=='HIT':
            hits[0]+=1
            print(f"\n[HIT #{p['n']}] slot16={p['slot16']} P={p['P']} lr={hex(p['lr']) if p['lr']>=0 else p['lr']}")
            print(f"   found={p['found']}")
            fh.write(json.dumps(p)+'\n'); fh.flush()
        else: print('[msg]',p)
    elif m.get('type')=='error':
        print('[JS ERR]',m.get('description'))
sc.on('message',on_msg); sc.load(); dev.resume(pid)
print(f"[*] waiting {SECS}s over natural burst...")
t0=time.time()
while time.time()-t0<SECS: time.sleep(0.5)
sess.detach(); fh.close()
print(f"[*] done. {hits[0]} HITs -> {OUT}")
