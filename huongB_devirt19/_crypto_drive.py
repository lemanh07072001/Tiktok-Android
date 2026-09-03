import frida,time,json
PKG="com.zhiliaoapp.musically"
js=open("_crypto_oracle.js").read()
msgs=[]
def om(m,d):
    if m.get('type')=='send':
        msgs.append(m['payload']); 
        json.dump(msgs,open("_crypto_msgs.json","w"))
        print("MSG",json.dumps(m['payload'])[:260],flush=True)
    elif m.get('type')=='error':
        print("JSERR",m.get('stack') or m.get('description'),flush=True)
dev=frida.get_usb_device(timeout=8)
print("spawn...",flush=True)
pid=dev.spawn([PKG]); print("pid",pid,flush=True)
sess=dev.attach(pid)
def on_detach(reason,*a): print("DETACHED reason=",reason,flush=True)
sess.on('detached',on_detach)
scr=sess.create_script(js); scr.on('message',om); scr.load()
dev.resume(pid); print("resumed",flush=True)
t0=time.time()
while time.time()-t0<25: time.sleep(0.5)
inits=[m for m in msgs if m.get('tag')=='INIT']
opens=[m for m in msgs if m.get('tag')=='OPEN']
print("=== OPENs",len(opens)," INITs",len(inits),flush=True)
armed=[m for m in inits if m.get('armed')]
print("=== armed INITs",len(armed),flush=True)
for m in armed[:30]: print("  ARMED",m.get('which'),"kb=",m.get('keyBytes'),"key=",m.get('key'),"iv=",m.get('iv'),"path=",m.get('path'),flush=True)
seen=set()
print("=== distinct INIT (which,key32,iv) ===",flush=True)
for m in inits:
    k=(m.get('which'),m.get('key32'),m.get('iv'))
    if k in seen: continue
    seen.add(k)
    print("  ",m.get('which'),"kb=",m.get('keyBytes'),"key32=",m.get('key32'),"iv=",m.get('iv'),"armed=",m.get('armed'),flush=True)
try: sess.detach()
except: pass
print("DONE",flush=True)
