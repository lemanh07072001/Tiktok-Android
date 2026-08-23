#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mem_scan_18.py — scan phone memory for device-stable #18 value -> locate PSK source region.
import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"
PAT="3c e2 76 6b 40 19 51 44 a9 3b 6c 0c cc 3e 13 07"
JS=r"""
const PAT='%s';
function region(addr){
  const mods=Process.enumerateModules();
  for(const m of mods){ if(addr.compare(m.base)>=0 && addr.compare(m.base.add(m.size))<0) return m.name+'+0x'+addr.sub(m.base).toString(16); }
  const r=Process.findRangeByAddress(addr); return r?('['+r.protection+' '+(r.file?r.file.path:'anon')+']'):'?';
}
rpc.exports={
  scan:function(){
    const hits=[];
    const ranges=Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
    for(const rg of ranges){
      try{ const res=Memory.scanSync(rg.base, rg.size, PAT);
        for(const h of res){ hits.push({addr:h.address.toString(), where:region(h.address), prot:rg.protection, file:(rg.file?rg.file.path:null)}); }
      }catch(e){}
      if(hits.length>40) break;
    }
    return hits;
  }
};
""" % PAT
dev=frida.get_usb_device(timeout=10)
p=next((x for x in dev.enumerate_processes() if "musically" in x.name or x.name=="TikTok"),None)
if not p: print("app not running; spawn"); pid=dev.spawn([PKG]); s=dev.attach(pid); dev.resume(pid); time.sleep(8)
else: print("attach",p.pid,p.name); s=dev.attach(p.pid)
sc=s.create_script(JS); sc.load()
for it in range(3):
    hits=sc.exports_sync.scan()
    print("\n[scan %d] %d hit(s) for #18:"%(it,len(hits)))
    for h in hits[:40]:
        print("   %s  %s  prot=%s file=%s"%(h["addr"],h["where"],h["prot"],h["file"]))
    time.sleep(3)
try: s.detach()
except: pass
