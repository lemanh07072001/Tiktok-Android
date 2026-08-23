#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_extract.py — tim #18 (device-stable) trong RW-mem metasec, dump lan can (=PSK context). Chay 2 cold-start de loc stable.
import frida,sys,os,time,json
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; TAG=os.environ.get("TAG","cs1"); WARM=int(os.environ.get("WARM","20"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_ctx_%s.json"%TAG)
JS=r"""
const P18='3c e2 76 6b 40 19 51 44 a9 3b 6c 0c cc 3e 13 07';
rpc.exports={
  scan:function(){
    const out=[]; const seenPage={};
    // metasec module rw ranges + anon rw ranges (<8MB)
    const mmeta=Process.findModuleByName('libmetasec_ov.so');
    const ranges=Process.enumerateRanges('rw-').filter(r=>{
      if(r.size>8*1024*1024) return false;
      if(r.file && r.file.path && r.file.path.indexOf('metasec')>=0) return true;
      if(!r.file) return true;               // anon heap
      return false;
    });
    let scanned=0;
    for(const rg of ranges){
      scanned+=rg.size; if(scanned>200*1024*1024) break;
      let res=[]; try{res=Memory.scanSync(rg.base,rg.size,P18);}catch(e){continue;}
      for(const h of res){
        const a=h.address;
        // dump 256 before + 256 after
        let ctx=null; try{ const s=a.sub(256); ctx=new Uint8Array(s.readByteArray(576)); }catch(e){}
        let cx=''; if(ctx){for(let i=0;i<ctx.length;i++)cx+=('0'+ctx[i].toString(16)).slice(-2);}
        let where=a.toString();
        if(mmeta && a.compare(mmeta.base)>=0 && a.compare(mmeta.base.add(mmeta.size))<0) where='metasec+0x'+a.sub(mmeta.base).toString(16);
        out.push({addr:a.toString(),where:where,file:(rg.file?rg.file.path:'anon'),ctx:cx});
        if(out.length>30) return out;
      }
    }
    return out;
  }
};
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn %s TAG=%s warm=%ds"%(PKG,TAG,WARM),flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS);sc.load();dev.resume(pid)
time.sleep(WARM)  # let app sign (feed) so #18 in memory
hits=sc.exports_sync.scan()
print("[*] %d hit(s) for #18"%len(hits),flush=True)
for h in hits[:12]: print("   %s  file=%s"%(h["where"],h["file"]),flush=True)
json.dump(hits,open(OUT,"w"))
try:s.detach()
except:pass
print("[*] saved -> %s"%OUT,flush=True)
