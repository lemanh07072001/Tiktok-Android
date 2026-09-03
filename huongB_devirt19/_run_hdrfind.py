import sys,os,json,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1]); SECS=int(sys.argv[2]) if len(sys.argv)>2 else 50
res={}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True); return
    p=m.get("payload") or {}; t=p.get("t")
    if t=="info": print("[*]",p["msg"],flush=True)
    elif t=="hdr":
        res.update(p); print("[HDR] slot16=%s nhits=%d"%(p["slot16"],p["nhits"]),flush=True)
        for it in p["info"]:
            print("   %s %s %s"%(it["addr"],it["prot"],it["file"] or "[anon]"),flush=True)
            print("     ctx:",it["ctx"],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID); sc=sess.create_script(open("_f_hdrfind.js",encoding="utf-8").read())
sc.on("message",on_msg); sc.load()
print("[*] attached %d %ds"%(PID,SECS),flush=True)
t0=time.time()
while time.time()-t0<SECS and not res: time.sleep(0.3)
try: sess.detach()
except: pass
json.dump(res,open("_hdrfind_out.json","w")); print("[DONE]",flush=True)
