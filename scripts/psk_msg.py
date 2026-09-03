#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_msg.py — 0x1280c0 doc MESSAGE word (x9=msg ptr). Bat message-start (x9 != last+4) & x9 NGOAI module
#   = data runtime bi hash (co the chua PSK). Dump message -> offline match #18/#19.
import frida,sys,os,json,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","55")); CAP=int(os.environ.get("CAP","300"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_msg.json")
JS=r"""
const MSEC='libmetasec_ov.so'; const KREAD=0x1280c0; const CAP=%d;
let base=null, mend=null, last=null, cap=0;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; base=m.base; mend=base.add(m.size);
  Interceptor.attach(base.add(KREAD),{onEnter(){
    if(cap>=CAP)return;
    const x9=this.context.x9; if(!x9)return;
    // new message start?
    const isSeq = last && x9.equals(last.add(4));
    last = x9;
    if(isSeq) return;                       // mid-sweep, skip
    // x9 in module = integrity check -> skip
    if(x9.compare(base)>=0 && x9.compare(mend)<0) return;
    // capture message start (heap/anon data)
    const data=hx(x9,320); if(!data)return;
    cap++;
    send({t:'msg',n:cap,ptr:x9.toString(),data:data});
  }});
  send({t:'info',msg:'hooked base='+base});
  return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
""" % CAP
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds CAP=%d"%(DUR,CAP),flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
evs=[]
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="msg":
        evs.append(p)
        if p["n"]<=5 or p["n"]%50==0: print("[msg #%d] ptr=%s data0:32=%s"%(p["n"],p["ptr"],p["data"][:64]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR and len(evs)<CAP:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(evs,open(OUT,"w"))
print("[*] captured %d messages -> %s"%(len(evs),OUT),flush=True)
