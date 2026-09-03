import frida,sys,time,json
JS='_vm_trace13.js'; TIMEOUT=int(sys.argv[1]) if len(sys.argv)>1 else 150
OUT='_vm_trace13.out.jsonl'
d=frida.get_usb_device(); pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open(JS).read())
f=open(OUT,'w')
def om(m,dd):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t','')
        f.write(json.dumps(p)+'\n'); f.flush()
        if t=='info': print(f"[info] base={p.get('base')}")
        elif t=='ready': print("[*] armed-waiting…")
        elif t=='mon': print(f"  [mon] armed={p['armed']} nFault={p['nFault']} wt={p['watchThread']}")
        elif t=='SM3': print(f"[SM3] slot16={p['slot16']} buf={p['buf']} lr={p['lr']}")
        elif t=='ARMED': print(f"[ARMED] buf={p['buf']} thread={p['thread']} want={p['wantThread']} nTh={p['nThreads']}")
        elif t=='ARM_ERR': print(f"[ARM_ERR] {p['e']}")
        elif t=='FAULT':
            print(f"[FAULT#{p['n']}] type={p['type']} pcOff={hex(p['pcOff']) if p['pcOff']>=0 else p['pcOff']} pcAbs={p['pcAbs']} mem={p['memOp']} bufNow={p['bufNow']}")
            print(f"   bt={[hex(x) if isinstance(x,int) and x>=0 else x for x in p['bt']][:12]}")
        elif t=='EH_ERR': print(f"[EH_ERR] {p['e']}")
    elif m.get('type')=='error': print("JSERR", m.get('description'))
sc.on('message',om); sc.load(); d.resume(pid)
print(f"[*] running up to {TIMEOUT}s")
dl=time.time()+TIMEOUT
while time.time()<dl: time.sleep(0.5)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
f.close(); print("[*] done ->",OUT)
