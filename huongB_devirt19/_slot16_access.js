// _slot16_access.js — locate a known slot16 in the header, arm MemoryAccessMonitor on its page, and log
// the accessing instruction PCs (from) + read/write. READ sites = consumers (0x9fd74 report-assembly, #19);
// a WRITE site = F (producer). Read sites reveal the header-struct access pattern (base+offset) to backtrack.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F=0x186420;  // hook a crypto call to know pool exists
const SM3=0xa0748, IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){} return 'anon?'; }
let base=null; let armed=false; const seenPC={}; let nacc=0; let slotAddr=null, slotPage=null;
function hentr16(a){ try{ const u=new Uint8Array(ptr(a).readByteArray(16)); let z=0,d={},asc=0; for(const b of u){ if(b===0)z++; if(b>=0x20&&b<=0x7e)asc++; d[b]=1; } return z<=2&&asc<12&&Object.keys(d).length>=12; }catch(e){ return false; } }
function findSlot(){ // scan rw- for a REAL header slot16: tag 020102000000 + value@+16 high-entropy
  const ranges=Process.enumerateRanges('rw-');
  for(const r of ranges){ if(r.size>32*1024*1024) continue;
    try{ const found=Memory.scanSync(r.base,r.size,'02 01 02 00 00 00');
      for(const f of found){ const entry=f.address.add(16);
        if(hentr16(entry)){ const kn=hx(entry.add(16),4);
          if(kn==='4b2d5645'||kn==='4b2d484f'||kn==='2d544e43'||kn==='4b2d5359'){ // K-VE/K-HO/-TNC/K-SY keyname
            return {addr:entry, val:hx(entry,16), hdr:true, keyname:hx(entry.add(16),12)}; } } } }catch(e){}
  }
  return null;
}
function arm(){
  const fnd=findSlot(); if(!fnd){ return false; }
  slotAddr=fnd.addr; slotPage=slotAddr.and(ptr('0xfffffffffffff000'));
  send({t:'located', slot16:fnd.val, addr:slotAddr.toString(), hdr:fnd.hdr, region:region(slotAddr)});
  const enable=()=>{ try{ MemoryAccessMonitor.enable([{base:slotPage,size:0x1000}], {onAccess(d){
    try{ if(nacc<200){ const from=d.from; const inMod=(from&&from.compare(base)>=0&&from.compare(base.add(0x200000))<0);
      const k=(inMod?('0x'+from.sub(base).toString(16)):from.toString())+':'+d.operation;
      if(!seenPC[k]){ seenPC[k]=1; nacc++; send({t:'access', from:(inMod?'0x'+from.sub(base).toString(16):from.toString()), inMod:inMod, op:d.operation, addr:d.address.toString()}); } } }catch(e){}
    finally{ try{ MemoryAccessMonitor.enable([{base:slotPage,size:0x1000}],{onAccess:arguments.callee}); }catch(e){} }
  }}); }catch(e){ send({t:'err',msg:'mam:'+e}); } };
  enable(); armed=true; return true;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; const lo=base, hi=base.add(m.size);
  // try to arm periodically until slot16 appears in header
  const iv=setInterval(function(){ if(!armed){ if(arm()) clearInterval(iv); } }, 2000);
  send({t:'info',msg:'slot16-access installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
