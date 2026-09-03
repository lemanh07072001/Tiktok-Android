import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
js=open("_store_spawn_oracle.js").read()
msgs=[]
def on_message(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p)
        print("MSG",json.dumps(p)[:300],flush=True)
    elif m.get('type')=='error':
        print("JSERR",m.get('stack') or m.get('description'),flush=True)
dev=frida.get_usb_device(timeout=8)
print("spawning...",flush=True)
pid=dev.spawn([PKG])
print("pid",pid,flush=True)
sess=dev.attach(pid)
scr=sess.create_script(js)
scr.on('message',on_message)
scr.load()
print("resumed",flush=True)
dev.resume(pid)
# collect startup window
t0=time.time()
while time.time()-t0<28:
    time.sleep(1)
try:
    dump=scr.exports_sync.dump()
except Exception as e:
    print("dumpexc",e,flush=True); dump=[]
json.dump({'msgs':msgs,'dump':dump},open("_spawn_capture.json","w"),indent=1)
# distinct EINIT tuples
tup=set()
for e in dump:
    if e.get('t')=='EINIT': tup.add((e.get('keyBytes'),e.get('key'),e.get('iv'),bool(e.get('armed'))))
print("=== distinct EINIT tuples:",len(tup),flush=True)
armed=[e for e in dump if e.get('t')=='EINIT' and e.get('armed')]
opens=[e for e in dump if e.get('t')=='OPEN']
print("OPENs:",len(opens)," armed-EINIT:",len(armed),flush=True)
for e in opens[:20]: print("  OPEN",e.get('path'),flush=True)
for e in armed[:20]: print("  ARMED-EINIT kb=%s key=%s iv=%s path=%s"%(e.get('keyBytes'),e.get('key'),e.get('iv'),e.get('path')),flush=True)
# also dump ALL distinct keys (for offline brute)
allk={}
for e in dump:
    if e.get('t')=='EINIT' and e.get('key'): allk[(e.get('key'),e.get('iv'),e.get('keyBytes'))]=allk.get((e.get('key'),e.get('iv'),e.get('keyBytes')),0)+1
print("=== ALL distinct (key,iv,kb):",len(allk),flush=True)
for (k,ivv,kb),c in list(allk.items())[:60]:
    print("  kb=%s x%d key=%s iv=%s"%(kb,c,k,ivv),flush=True)
try: sess.detach()
except: pass
print("DONE",flush=True)
