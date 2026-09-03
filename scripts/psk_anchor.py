#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_anchor.py — anchor tai SHA256 K-table read (metasec+0x1280c0). Bat luc x9==&K[0] (round0=dau compression),
#   dump registers + memory quanh cac con tro -> tim SHA256 input block (chua PSK) + state H.
import frida,sys,os,json,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","55")); CAP=int(os.environ.get("CAP","60"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_anchor.json")
JS=r"""
const MSEC='libmetasec_ov.so'; const KREAD=0x1280c0, KT=0x19b540, IVOFF=0x19b520;
const SIGN=0x9af80, SG=0x9ecc0; const CAP=%d;
let SIGNING=0, base=null, K0=null, cap=0;
function hx(p,n){ try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function inMapped(p){ try{return !!Process.findRangeByAddress(p);}catch(e){return false;} }
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; base=m.base; K0=base.add(KT);
  [SG,SIGN].forEach(o=>Interceptor.attach(base.add(o),{onEnter(){SIGNING++;},onLeave(){if(SIGNING>0)SIGNING--;}}));
  Interceptor.attach(base.add(KREAD),{
    onEnter(){
      if(!SIGNING||cap>=CAP)return;
      const ctx=this.context;
      let x9=ctx.x9;
      if(!x9 || x9.compare(K0)!==0) return;   // only round-0 (x9 points to K[0])
      cap++;
      const regs={}; const mem={};
      for(let i=0;i<=28;i++){ const rn='x'+i; const p=ctx[rn]; regs[rn]=p?p.toString():null;
        if(p && inMapped(p)){ const h=hx(p,96); if(h) mem[rn]=h; } }
      regs['sp']=ctx.sp.toString(); { const h=hx(ctx.sp,160); if(h) mem['sp']=h; }
      send({t:'anchor',n:cap,regs:regs,mem:mem});
    }
  });
  send({t:'info',msg:'anchored base='+base+' K0='+K0});
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
    elif p.get("t")=="anchor":
        evs.append(p)
        if p["n"]<=3 or p["n"]%15==0: print("[anchor #%d] regs-with-mem=%d"%(p["n"],len(p["mem"])),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR and len(evs)<CAP: time.sleep(0.5)
try:s.detach()
except:pass
json.dump(evs,open(OUT,"w"))
print("[*] captured %d anchor events -> %s"%(len(evs),OUT),flush=True)
