import frida,sys,time,json
JS='_vm_trace13b.js'; T=int(sys.argv[1]) if len(sys.argv)>1 else 60
OUT='_vm_trace13b.out.jsonl'
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read()); f=open(OUT,'w')
def om(m,dd):
    if m.get('type')=='send':
        p=m['payload']; f.write(json.dumps(p)+'\n'); f.flush()
        if p.get('t')=='C': print(f"[C#{p['i']}] slot16={p['slot16']} buf={p['buf']} tid={p['tid']} lr={p['lr']}")
        elif p.get('t')=='mon': print(f"  [mon] n={p['n']}")
        elif p.get('t')=='ready': print("[*] waiting…")
    elif m.get('type')=='error': print("JSERR",m.get('description'))
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+T
while time.time()<dl: time.sleep(0.4)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
f.close(); print("done ->",OUT)
