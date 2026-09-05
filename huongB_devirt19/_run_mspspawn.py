import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 60
JS=open("_mspspawn.js").read()
seen=[]
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];k=p.get("k")
        if k in("INSTALLED","WAIT_DLOPEN","ERR"):print("[*]",p,flush=True)
        elif k=="STORE":print("[STORE]",p.get("kind"),flush=True);seen.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (mspspawn store-plaintext)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:
    log=sc.exports_sync.dump() if hasattr(sc,"exports_sync") else sc.exports.dump()
except Exception as e:
    log=[];print("[dump err]",e,flush=True)
json.dump(log,open("cap.noindex/ce0516_store_plain.json","w"),indent=1)
print(f"\n=== {len(log)} store-plaintext captures ===",flush=True)
for i,e in enumerate(log[:12]):
    k=e.get("kind")
    for fld in("pre0","pre1"):
        v=e.get(fld)
        if v and v.get("hex"):
            hx=v["hex"];asc="".join(chr(int(hx[j:j+2],16)) if 32<=int(hx[j:j+2],16)<127 else "." for j in range(0,min(len(hx),200),2))
            print(f" [{i}] {k}.{fld} sz={v['sz']} ascii={asc[:90]}",flush=True)
try:s.detach()
except:pass
