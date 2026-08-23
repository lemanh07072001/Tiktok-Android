#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cap_init_seq.py — hook dispatcher 0x11a1e0 tren phone, log moi cmd luc startup = chuoi init can replay.
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","20"))
JS=r"""
const MSEC='libmetasec_ov.so'; const DISP=0x11a1e0;
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; const base=m.base;
  let n=0;
  Interceptor.attach(base.add(DISP),{onEnter(a){
    if(n>=120)return; n++;
    const cmd=a[2].toInt32()>>>0; const i2=a[3]?a[3].toInt32():0;
    // try read arg5 as string (device_id/aid) if pointer
    let s=null; try{ const p=a[5]; if(p && !p.isNull()){ /* jstring or char* - skip deref, just note non-null */ s='obj'; } }catch(e){}
    send({t:'disp',n:n,cmd:'0x'+cmd.toString(16),i2:i2,a5:s});
  }});
  send({t:'info',msg:'hooked disp @'+base.add(DISP)});
  return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds (startup init seq)"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
seq=[]
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="disp":
        seq.append(p);print("  [%3d] cmd=%-10s i2=%-5d a5=%s"%(p["n"],p["cmd"],p["i2"],p["a5"]),flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.3)
try:s.detach()
except:pass
# summarize order of distinct cmds
print("\n[*] init cmd sequence (first occurrence order):")
seen=[]
for p in seq:
    if p["cmd"] not in seen: seen.append(p["cmd"])
print("   ",  " -> ".join(seen))
