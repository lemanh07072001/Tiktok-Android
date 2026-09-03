#!/usr/bin/env python3
"""Attach to the ALREADY-RUNNING app (no force-stop, login-safe), load a Frida
script, drive gentle UI to stimulate heartbeats/signing, collect send() JSON.
Usage: _run_ctx.py <script.js> <pid> <secs> <out.jsonl>"""
import sys,json,time,frida,subprocess
DEV='emulator-5554'
JS=sys.argv[1]; PID=int(sys.argv[2]); SECS=int(sys.argv[3]) if len(sys.argv)>3 else 75
OUT=sys.argv[4] if len(sys.argv)>4 else JS.replace('.js','.out.jsonl')
code=open(JS).read()
def sh(*a):
    try: subprocess.run(['adb','-s',DEV,'shell',*a],timeout=8,capture_output=True)
    except Exception as e: print('[sh err]',e,flush=True)
dev=frida.get_usb_device()
print(f'[*] attaching pid {PID} (no restart)...',flush=True)
sess=dev.attach(PID); sc=sess.create_script(code)
caps=0; ready=False
f=open(OUT,'w')
def on(m,d):
    global caps,ready
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t','')
        if t=='info': print('[info]',p.get('msg'),p.get('base'),flush=True)
        elif t=='ready': ready=True; print('[*] hooks installed',flush=True)
        elif t=='mon': print(f'  [mon] n={p.get("n")}',flush=True)
        elif t=='CTX':
            caps+=1
            f.write(json.dumps(p)+'\n'); f.flush()
            print(f'[CTX #{p.get("seq")}] w1={p.get("w1")} lr={p.get("lr")} outAtX8={p.get("outAtX8")} outAtX0={p.get("outAtX0")}',flush=True)
        else: print('[msg]',p,flush=True)
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'),flush=True)
sc.on('message',on); sc.load()
print('[*] loaded; driving UI + waiting for heartbeat/signing...',flush=True)
t0=time.time(); i=0
while time.time()-t0<SECS:
    # gentle feed scroll every ~6s to stimulate network (heartbeat fires on its own)
    if i%3==0: sh('input','swipe','540','1500','540','600','220')
    i+=1; time.sleep(2)
    if caps>=8: print('[*] enough captures, stopping early',flush=True); break
try: sess.detach()
except Exception: pass
f.close()
print(f'[*] done. captures={caps}  out={OUT}',flush=True)
