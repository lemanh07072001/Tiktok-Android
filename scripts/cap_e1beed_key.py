#!/usr/bin/env python3
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","40"))
JS=r"""
const LIB='libmetasec_ov.so'; const ONESHOT=0x1539d0, UPDATE=0x1526b8;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function txt(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(LIB); if(!m)return false;
  // sha1_oneshot(data, len, out)
  Interceptor.attach(m.base.add(ONESHOT),{
    onEnter(a){ this.d=a[0]; this.n=a[1].toInt32(); this.o=a[2]; },
    onLeave(){ if(!this.o)return; const dg=hx(this.o,20); if(!dg)return;
      if(dg.indexOf('e1beed15')===0 || dg.indexOf('302eacd6')===0 || dg.indexOf('58abed2b')===0 || dg.indexOf('be1612d2')===0){
        send({t:'hit',out:dg,inhex:hx(this.d,Math.min(this.n,64)),intxt:txt(this.d,Math.min(this.n,64)),len:this.n});
      }
    }
  });
  send({t:'info',msg:'hooked sha1_oneshot'}); return true;
}
if(Process.findModuleByName(LIB))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(LIB)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="hit":print("[KEY] sha1=%s <= keyname(len=%d): txt='%s' hex=%s"%(p["out"][:12],p["len"],p["intxt"],p["inhex"]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
