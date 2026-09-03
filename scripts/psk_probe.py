#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_probe.py — capture INNER report (memcpy hook) fresh cold-start -> so #18 stability.
import frida, sys, os, json, time
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
PKG=os.environ.get("PKG","com.zhiliaoapp.musically")
DUR=int(os.environ.get("DUR","50"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_probe_reports.jsonl")
JS=r"""
const LIB='libmetasec_ov.so';
const GATES=[0x9ecc0,0x9af80];   // sign fns -> SG window
let SIGNING=0;
function hx(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(LIB); if(!m) return false;
  const base=m.base;
  GATES.forEach(off=>{ try{ Interceptor.attach(base.add(off),{
    onEnter(){SIGNING++;}, onLeave(){ if(SIGNING>0)SIGNING--; }
  }); }catch(e){} });
  const memcpy=Module.findGlobalExportByName('memcpy')||Module.findExportByName('libc.so','memcpy');
  const seen={};
  Interceptor.attach(memcpy,{
    onEnter(a){
      if(!SIGNING) return;
      const n=a[2].toInt32(); if(n<450||n>820) return;
      const src=a[1]; if(src.isNull()) return;
      let b0,b1,b2;
      try{ b0=src.readU8(); }catch(e){ return; }
      if(b0!==0x08) return;
      try{ b1=src.add(1).readU8(); b2=src.add(2).readU8(); }catch(e){ return; }
      if(b1!==0xd2||b2!==0xa4) return;   // magic prefix 08 d2 a4 (report field1)
      let rep; try{ rep=hx(src.readByteArray(n)); }catch(e){ return; }
      const key=rep.slice(0,16)+':'+n;
      if(seen[key]) return; seen[key]=1;
      send({t:'report',len:n,hex:rep});
    }
  });
  send({t:'info',msg:'hooked base='+base});
  return true;
}
if(Process.findModuleByName(LIB)) install();
else { const dl=Module.findGlobalExportByName('android_dlopen_ext');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(LIB)>=0)install();}}); }
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds cold-start #2"%DUR,flush=True)
pid=dev.spawn([PKG]); s=dev.attach(pid); sc=s.create_script(JS)
reps=[]
def onmsg(m,d):
    if m.get("type")=="error": print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info": print("[*]",p["msg"],flush=True)
    elif p.get("t")=="report":
        reps.append(p); print("[REPORT] len=%d prefix=%s"%(p["len"],p["hex"][:24]),flush=True)
sc.on("message",onmsg); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR: time.sleep(0.5)
try: s.detach()
except Exception: pass
f=open(OUT,"w",encoding="utf-8")
for r in reps: f.write(json.dumps(r)+"\n")
f.close()
print("\n[*] captured %d distinct report(s) -> %s"%(len(reps),OUT),flush=True)
