#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","18"))
JS=r"""
const MSEC='libmetasec_ov.so'; const DISP=0x11a1e0; const PS=Process.pointerSize;
function jstr(env,j){ try{ if(!j||j.isNull())return null; const f=env.readPointer().add(169*PS).readPointer();
  const p=new NativeFunction(f,'pointer',['pointer','pointer','pointer'])(env,j,ptr(0)); return p.isNull()?null:p.readCString(); }catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; const base=m.base;
  let seen={};
  Interceptor.attach(base.add(DISP),{onEnter(a){
    const cmd=a[2].toInt32()>>>0; if(cmd===0x1000001)return;
    const key=cmd; if(seen[key]&&seen[key]>=3)return; seen[key]=(seen[key]||0)+1;
    const i2=a[3]?a[3].toInt32():0; const lng=a[4]?a[4].toString():'0';
    let s5=jstr(a[0],a[5]); let s6=null;
    send({t:'d',cmd:'0x'+cmd.toString(16),i2:i2,lng:lng,s5:s5});
  }});
  send({t:'info',msg:'ok'});return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*] hooked",flush=True)
    elif p.get("t")=="d":print("  cmd=%-11s i2=%-6d long=%-14s arg5=%s"%(p["cmd"],p["i2"],p["lng"],p["s5"]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.3)
try:s.detach()
except:pass
