import frida,sys,time,json
JS='_vm_trace17.js'; T=int(sys.argv[1]) if len(sys.argv)>1 else 40
OUT='_vm_trace17.out.json'
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read())
got={}
def om(m,dd):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t')
        if t=='DUMP':
            got.update(p); print(f"[DUMP] slot16={p['slot16']} total={p['total']} count={p['count']}", flush=True)
        elif t=='mon': print(f"[mon] seq={p['seq']} dumped={p['dumped']}", flush=True)
        elif t=='ready': print("[*] ready", flush=True)
        elif t=='info': print(f"[info] base={p['base']} size={p['size']}", flush=True)
    elif m.get('type')=='error': print("JSERR", m.get('description'), flush=True)
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+T
while time.time()<dl and 'DUMP' not in got.get('t',''): time.sleep(0.3)
if got: json.dump(got, open(OUT,'w'))
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
print("done ->",OUT,"have=",bool(got), flush=True)
