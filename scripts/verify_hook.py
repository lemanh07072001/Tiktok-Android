#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","30"))
JS=r"""
const MSEC='libmetasec_ov.so'; const SVC=0x16c190;
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false;
  let syscallCount={}; let opens=0;
  Interceptor.attach(m.base.add(SVC),{onEnter(a){
    const c=this.context; const x8=c.x8?c.x8.toInt32():-1;
    syscallCount[x8]=(syscallCount[x8]||0)+1;
    if(x8===56){ opens++;
      try{ const path=c.x1.readCString(); if(path && (path.indexOf('/files/')>=0||path.indexOf('mssdk')>=0||path.indexOf('.ms')>=0)) send({t:'file',path:path}); }catch(e){}
    }
  }});
  setTimeout(()=>{ send({t:'stats', total:Object.keys(syscallCount).length, opens:opens, top:Object.entries(syscallCount).sort((a,b)=>b[1]-a[1]).slice(0,12)}); }, 20000);
  send({t:'info',msg:'hooked'}); return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
files=set()
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info": print("[*] hooked",flush=True)
    elif p.get("t")=="file": files.add(p["path"].split('/')[-1] if '.ms' in p["path"] else p["path"][-40:])
    elif p.get("t")=="stats": print("[STATS] distinct-syscalls=%d openat-count=%d top-syscalls(x8:count):"%(p["total"],p["opens"]),p["top"],flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(DUR)
try:s.detach()
except:pass
print("\n=== files metasec opened (openat, /files/ or .ms) ==="); [print("  ",f) for f in sorted(files)]
