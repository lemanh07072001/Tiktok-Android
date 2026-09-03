import os,time,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
# attach to running tiktok
procs=[p for p in dev.enumerate_processes() if 'musical' in (p.name or '').lower() or p.name=='TikTok']
if not procs:
    print("no tiktok running; spawn"); pid=dev.spawn(["com.zhiliaoapp.musically"]); dev.resume(pid); time.sleep(4)
else:
    pid=procs[0].pid; print("attach",pid,procs[0].name)
sess=dev.attach(pid)
ready={"v":False}
def on_msg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"),flush=True)
    else:
        p=m.get("payload") or {}
        if p.get("t")=="ready": ready["v"]=True
sc=sess.create_script(open("_cm_probe.js",encoding="utf-8").read()); sc.on("message",on_msg); sc.load()
time.sleep(0.5)
# pick a busy thread: enumerate threads, follow the main/first few
th=dev.enumerate_processes  # not per-thread; use script thread enum
tids=sc.exports_sync.__dict__ if False else None
import json
# get threads via a quick script call
sc2=sess.create_script("rpc.exports={threads:function(){return Process.enumerateThreads().map(t=>t.id);}}"); sc2.load()
allt=sc2.exports_sync.threads()
print("threads:",allt[:8],"...(%d)"%len(allt))
r=sc.exports_sync.go(allt[0]); print("go:",r)
time.sleep(2)
print("store_count after 2s:",sc.exports_sync.read())
sc.exports_sync.stop(allt[0])
print("OK CModule+Stalker works")
