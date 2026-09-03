import os,time,frida,json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PKG="com.zhiliaoapp.musically"; got=[]
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="kv":
        got.append(p)
        print("\n[KV #%d] len=%d kvPos=%d ra=%s"%(p["i"],p["len"],p["kvBytePos"],p["ra"]),flush=True)
        print("   src=%s (%s)  dst=%s (%s)"%(p["src"],p["srcRegion"],p["dst"],p["dstRegion"]),flush=True)
        print("   val16(before K-VERSION) = %s"%p["val16"],flush=True)
        print("   srcHead=%s"%p["srcHead"],flush=True)
        print("   stack:",flush=True)
        for s in p["stack"][:14]: print("      ",s,flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); sess=dev.attach(pid)
sc=sess.create_script(open("_store_key_hook.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load(); dev.resume(pid)
print("[*] spawned",pid,flush=True)
t0=time.time()
while time.time()-t0<80 and len(got)<8: time.sleep(0.4)
try: sess.detach()
except: pass
json.dump(got,open("_store_key_out.json","w"))
print("\n[DONE] %d captured"%len(got),flush=True)
