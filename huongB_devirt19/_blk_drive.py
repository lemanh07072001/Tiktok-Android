import frida,time,json
PKG="com.zhiliaoapp.musically"
js=open("_blk_oracle.js").read()
msgs=[]
def om(m,d):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p)
        json.dump(msgs,open("_blk_msgs.json","w"))
        t=p.get('tag')
        if t in('STOREHIT','ARMED','READY'): print("MSG",json.dumps(p)[:300],flush=True)
    elif m.get('type')=='error':
        print("JSERR",m.get('stack') or m.get('description'),flush=True)
dev=frida.get_usb_device(timeout=8)
print("spawn...",flush=True)
pid=dev.spawn([PKG]); print("pid",pid,flush=True)
sess=dev.attach(pid)
sess.on('detached',lambda r,*a: print("DETACHED",r,flush=True))
scr=sess.create_script(js); scr.on('message',om); scr.load()
dev.resume(pid); print("resumed",flush=True)
t0=time.time()
while time.time()-t0<35: time.sleep(0.5)
hits=[m for m in msgs if m.get('tag')=='STOREHIT']
keys=[m for m in msgs if m.get('tag')=='KEY']
print("=== STOREHITs",len(hits)," distinct KEYs",len(keys),flush=True)
for h in hits[:40]:
    print("  HIT",h.get('op'),h.get('store'),"matchIn=",h.get('matchIn'),"matchOut=",h.get('matchOut'),"win=",h.get('win'),flush=True)
    print("     in =",h.get('in16')," out=",h.get('out16'),flush=True)
    print("     key16=",(h.get('sched') or '')[:32],flush=True)
print("=== distinct keys ===",flush=True)
for k in keys: print("  KEY",k.get('op'),k.get('k16'),"sched32=",k.get('sched32'),flush=True)
try: sess.detach()
except: pass
print("DONE",flush=True)
