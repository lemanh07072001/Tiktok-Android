import frida,sys,time,json
JS='_vm_trace14.js'; T=int(sys.argv[1]) if len(sys.argv)>1 else 60
OUT='_vm_trace14.out.json'
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read())
hits=[]
def om(m,dd):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t')
        if t=='HIT':
            hits.append(p)
            print(f"[HIT] v={p['v']}")
            print(f"   x19={p['x19']} x21={p['x21']} x23={p['x23']}")
            print(f"   src={p['src']}")
        elif t=='mon': print(f"  [mon] got={p['got']} distinct={p['distinct']}")
        elif t=='ready': print("[*] waiting…")
        elif t=='info': print(f"[info] base={p['base']}")
    elif m.get('type')=='error': print("JSERR", m.get('description'))
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+T
while time.time()<dl and len(hits)<6: time.sleep(0.3)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
json.dump(hits, open(OUT,'w'), indent=1)
print("done ->",OUT,"hits=",len(hits))
