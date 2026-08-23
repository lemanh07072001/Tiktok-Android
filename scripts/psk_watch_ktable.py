#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_watch_ktable.py — MemoryAccessMonitor tren SHA256 K-table -> PC ham internal SHA256 transform.
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","50"))
JS=r"""
const MSEC='libmetasec_ov.so'; const KT_OFF=0x19b540, KT_SZ=256;
function loc(a){ const m=Process.findModuleByAddress(a); return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString(); }
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false;
  const kt=m.base.add(KT_OFF);
  send({t:'info',msg:'K-table @'+kt+' base='+m.base});
  const hits={};
  try{
    MemoryAccessMonitor.enable([{base:kt,size:KT_SZ}],{
      onAccess:function(d){
        const from=d.from; const key=from.toString();
        if(hits[key]){ return; } hits[key]=1;
        send({t:'access',op:d.operation,from:loc(from),addr:d.address.toString(),idx:d.rangeIndex});
        // re-enable for continued detection of OTHER PCs
        try{ MemoryAccessMonitor.enable([{base:kt,size:KT_SZ}],this); }catch(e){}
      }
    });
    return true;
  }catch(e){ send({t:'info',msg:'MAM fail '+e}); return true; }
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
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="access":print("[K-READ] %s op=%s from=%s"%(p["addr"],p["op"],p["from"]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("[*] done",flush=True)
