#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_backtrace.py — bat memcpy chep #18 (16B unique, device-stable) trong sign -> backtrace -> ham sinh pskHash.
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","60"))
JS=r"""
const MSEC='libmetasec_ov.so'; const SIGN=0x9af80, SG=0x9ecc0;
const P18='3ce2766b40195144a93b6c0ccc3e1307';
let SIGNING=0; let base=null;
function hx(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function bt(ctx){ try{ return Thread.backtrace(ctx,Backtracer.ACCURATE).slice(0,8).map(a=>{
   const m=Process.findModuleByName(MSEC); if(m&&a.compare(m.base)>=0&&a.compare(m.base.add(m.size))<0) return MSEC+'+0x'+a.sub(m.base).toString(16);
   const mm=Process.findModuleByAddress(a); return mm?(mm.name+'+0x'+a.sub(mm.base).toString(16)):a.toString();
 }); }catch(e){return[];} }
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; base=m.base;
  [SG,SIGN].forEach(o=>Interceptor.attach(base.add(o),{onEnter(){SIGNING++;},onLeave(){if(SIGNING>0)SIGNING--;}}));
  const fns=['memcpy','memmove'];
  let done=0;
  fns.forEach(fn=>{ const p=Module.findGlobalExportByName(fn); if(!p)return;
    Interceptor.attach(p,{onEnter(a){
      if(!SIGNING||done>6)return; const n=a[2].toInt32(); if(n!==16&&n!==32&&n!==48)return;
      let src; try{src=hx(a[1].readByteArray(16));}catch(e){return;}
      if(src!==P18) return;
      done++;
      send({t:'hit',fn:fn,len:n,dst:a[0].toString(),src:a[1].toString(),bt:bt(this.context)});
    }});
  });
  send({t:'info',msg:'installed base='+base});
  return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds - luot feed de trigger sign"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="hit":
        print("\n[HIT #18-copy] %s len=%d dst=%s"%(p["fn"],p["len"],p["dst"]),flush=True)
        for f in p["bt"]: print("     <- "+f,flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("\n[*] done",flush=True)
