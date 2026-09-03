#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","45"))
JS=r"""
const MSEC='libmetasec_ov.so'; const SVC=0x16c190;
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false;
  Interceptor.attach(m.base.add(SVC),{onEnter(a){
    const c=this.context; const x8=c.x8?c.x8.toInt32():-1;
    if(x8===56){ // openat
      try{ const path=c.x1.readCString(); if(path && path.indexOf('mssdk/ov')>=0){ send({t:'open',fn:path.split('/').pop()}); } }catch(e){}
    }
  }});
  send({t:'info',msg:'hooked svc@0x16c190'}); return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
seen={}
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="open": seen[p["fn"]]=seen.get(p["fn"],0)+1
    elif p.get("t")=="info": print("[*]",p["msg"],flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(DUR)
try:s.detach()
except:pass
print("\n=== PHONE metasec openat (.msdata/mssdk/ov) via syscall ===")
for f,c in sorted(seen.items()): print("  x%-2d %s"%(c,f))
print("\n=== unidbg opened: 286707,302e,58ab,5bbd,b99e,be16,d97b,db4d,092f,589c,9b8e (NOT e1beed) ===")
