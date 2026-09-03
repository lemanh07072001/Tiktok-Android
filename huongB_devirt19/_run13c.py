import frida,sys,time,json
JS='_vm_trace13c.js'; T=int(sys.argv[1]) if len(sys.argv)>1 else 45
OUT='_vm_trace13c.out.json'
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read())
hits=[]
def om(m,dd):
    if m.get('type')=='send':
        p=m['payload']
        if p.get('t')=='HIT':
            hits.append(p)
            print(f"[HIT#{p['i']}] slot16={p['slot16']} buf={p['buf']}")
            for fr in p['bt'][:14]:
                print(f"    {hex(fr['off']) if fr['off']>=0 else '     '+fr['abs']}")
        elif p.get('t')=='mon': print(f"  [mon] got={p['got']}")
        elif p.get('t')=='ready': print("[*] waiting…")
        elif p.get('t')=='info': print(f"[info] base={p['base']}")
    elif m.get('type')=='error': print("JSERR", m.get('description'))
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+T
while time.time()<dl and len(hits)<4: time.sleep(0.3)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
json.dump(hits, open(OUT,'w'), indent=1)
print("done ->",OUT, "hits=",len(hits))
