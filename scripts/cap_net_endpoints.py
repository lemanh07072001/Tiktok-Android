#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","45"))
JS=r"""
const MSEC='libmetasec_ov.so'; const DISP=0x11a1e0; const PS=Process.pointerSize;
function jstr(env,j){ try{ if(!j||j.isNull())return null; const f=env.readPointer().add(169*PS).readPointer();
  const p=new NativeFunction(f,'pointer',['pointer','pointer','pointer'])(env,j,ptr(0)); return p.isNull()?null:p.readCString(); }catch(e){return null;} }
function cstr(p){ try{return p.isNull()?null:p.readCString();}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false;
  Interceptor.attach(m.base.add(DISP),{onEnter(a){
    const cmd=a[2].toInt32()>>>0; if(cmd!==0x30001) return;
    // arg5 (a[5]) = URL (jstring hoac char*)
    let u=jstr(a[0],a[5]); if(!u) u=cstr(a[5]);
    if(u && u.indexOf('mssdk')>=0 || (u && (u.indexOf('/ms/')>=0||u.indexOf('/sdi/')>=0||u.indexOf('/kms')>=0||u.indexOf('register')>=0))){
      // chi lay path+first-param cho gon
      const short=u.split('?')[0];
      send({t:'net', url:short});
    }
  }});
  send({t:'info',msg:'hooked disp 0x30001'});
  return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
seen={}
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="net":
        u=p["url"]; seen[u]=seen.get(u,0)+1
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("\n=== PHONE metasec network endpoints (0x30001) ===")
for u,c in sorted(seen.items()): print("  x%-2d %s"%(c,u))
print("\n(unidbg goi: ms/dyn/task, ms/get_seed, sdi/get_token)")
