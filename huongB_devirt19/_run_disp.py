import frida,sys,time,json
JS='_vm_probe_disp.js'; T=int(sys.argv[1]) if len(sys.argv)>1 else 60
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read())
last={}
def om(m,dd):
    global last
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t')
        if t=='mon':
            last=p; print(f"[mon] disp={p['nDisp']} consume={p['nConsume']} nonzero={p['nNonzero']} dispAtFirstNZ={p['dispAtFirstNZ']}", flush=True)
        elif t=='ready': print("[*] ready", flush=True)
        elif t=='info': print(f"[info] base={p['base']}", flush=True)
    elif m.get('type')=='error': print("JSERR", m.get('description'), flush=True)
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+T
while time.time()<dl: time.sleep(0.5)
print("FINAL", json.dumps(last), flush=True)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
