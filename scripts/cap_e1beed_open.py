#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","45"))
JS=r"""
const MSEC='libmetasec_ov.so';
function bt(ctx){ try{ return Thread.backtrace(ctx,Backtracer.ACCURATE).slice(0,10).map(a=>{
  const m=Process.findModuleByName(MSEC); if(m&&a.compare(m.base)>=0&&a.compare(m.base.add(m.size))<0) return MSEC+'+0x'+a.sub(m.base).toString(16);
  const mm=Process.findModuleByAddress(a); return mm?(mm.name+'+0x'+a.sub(mm.base).toString(16)):a.toString();
 }); }catch(e){return[];} }
function hook(name){ const p=Module.findGlobalExportByName(name); if(!p)return;
  Interceptor.attach(p,{onEnter(a){ let path; try{path=(name==='openat')?a[1].readCString():a[0].readCString();}catch(e){return;}
    if(path && path.indexOf('mssdk')>=0 && path.indexOf('.ms')>=0){ send({t:'open',fn:name,path:path.split('/').pop(),bt:bt(this.context)}); } }});
}
setTimeout(function(){ ['open','openat'].forEach(hook); send({t:'info',msg:'hooked open/openat for e1beed'}); }, 500);
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="open":
        print("\n[OPEN e1beed] %s(%s) — caller chain:"%(p["fn"],p["path"][:20]),flush=True)
        for f in p["bt"]: print("    <- "+f,flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("[done]",flush=True)
