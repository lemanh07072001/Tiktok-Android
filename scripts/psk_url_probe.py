#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_url_probe.py — correlate URL (sign arg0) -> report has pskHash(#18) or not. Maps which endpoints need PSK.
import frida,sys,os,json,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","70"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_url_map.json")
JS=r"""
const MSEC='libmetasec_ov.so'; const SIGN=0x9af80, SG=0x9ecc0;
let SIGNING=0; const URL={}; // tid -> url
function hx(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; const base=m.base;
  Interceptor.attach(base.add(SG),{onEnter(){SIGNING++;},onLeave(){if(SIGNING>0)SIGNING--;}});
  Interceptor.attach(base.add(SIGN),{onEnter(a){SIGNING++; let u=null; try{u=a[0].readCString();}catch(e){} URL[this.threadId]=u;},onLeave(){if(SIGNING>0)SIGNING--;}});
  const memcpy=Module.findGlobalExportByName('memcpy'); const seen={};
  Interceptor.attach(memcpy,{onEnter(a){if(!SIGNING)return;const n=a[2].toInt32();if(n<450||n>820)return;const s=a[1];let b0;try{b0=s.readU8();}catch(e){return;}if(b0!==0x08)return;let b1,b2;try{b1=s.add(1).readU8();b2=s.add(2).readU8();}catch(e){return;}if(b1!==0xd2||b2!==0xa4)return;let r;try{r=hx(s.readByteArray(n));}catch(e){return;}const k=r.slice(0,20)+n;if(seen[k])return;seen[k]=1;send({t:'report',len:n,hex:r,url:URL[this.threadId]||null});}});
  send({t:'info',msg:'installed'}); return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds - luot feed + thu 1 action (like/follow) neu duoc"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
reps=[]
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="report":
        reps.append(p);print("[REP] len=%d url=%s"%(p["len"],(p.get("url") or "?")[:70]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(reps,open(OUT,"w"))
print("[*] %d reports -> %s"%(len(reps),OUT),flush=True)
