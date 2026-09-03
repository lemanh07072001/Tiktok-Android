#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","45"))
JS=r"""
function hook(name){ const p=Module.findGlobalExportByName(name); if(!p)return;
  Interceptor.attach(p,{onEnter(a){ let path; try{path=(name==='openat')?a[1].readCString():a[0].readCString();}catch(e){return;}
    if(path && path.indexOf('mssdk/ov')>=0){ const fn=path.split('/').pop(); send({t:'open',fn:fn}); } }});
}
setTimeout(function(){ ['open','openat'].forEach(hook); send({t:'info',msg:'hooked'}); }, 500);
"""
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
seen={}
def om(m,d):
    p=m.get("payload") or {}
    if p.get("t")=="open": seen[p["fn"]]=seen.get(p["fn"],0)+1
    elif p.get("t")=="info": print("[*] hooked",flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(DUR)
try:s.detach()
except:pass
print("\n=== PHONE .msdata/mssdk/ov files opened (warm launch) ===")
for f,c in sorted(seen.items()): print("  x%-2d %s"%(c,f))
