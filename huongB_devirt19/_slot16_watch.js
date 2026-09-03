// _slot16_watch.js — NON-PERTURBING producer trace via MemoryAccessMonitor (software watchpoint,
// page-protection, no code patching). Hook 0x1384e4 only to read x4=outbuf (reading x4 is not perturbed).
// Arm MemoryAccessMonitor on the outbuf page; the first WRITE to it = F's slot16 store -> its PC = producer.
'use strict';
const SO='libmetasec_ov.so', FCALL=0x1384e4;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const lo=base, hi=base.add(0x200000); let n=0; let arming=false;
  function resolve(a){ try{ const mm=Process.findModuleByAddress(a); if(mm) return mm.name+'+0x'+a.sub(mm.base).toString(16);}catch(e){} return a.toString(); }
  Interceptor.attach(base.add(FCALL),{onEnter(){
    if(n>=3||arming) return; n++;
    const c=this.context; const x4=c.x4;                 // outbuf (std::string obj) — reading x4 is safe
    // watch the outbuf object page AND the string's heap data page (deref [x4+0x10] = data ptr for long strings)
    const ranges=[{base:ptr(x4).and(ptr('0xfffffffffffff000')), size:0x1000}];
    try{ const dp=x4.add(0x10).readPointer(); if(!dp.isNull()) ranges.push({base:dp.and(ptr('0xfffffffffffff000')),size:0x1000}); }catch(e){}
    arming=true;
    try{
      MemoryAccessMonitor.enable(ranges, { onAccess(d){
        const from=d.from;
        send({t:'access', op:d.operation, addr:d.address.toString(),
              from:from.toString(), from_res:resolve(from),
              in_so:(from.compare(lo)>=0 && from.compare(hi)<0),
              from_off:(from.compare(lo)>=0&&from.compare(hi)<0)?('0x'+from.sub(base).toString(16)):null });
      }});
      send({t:'info',msg:'MemoryAccessMonitor armed on outbuf ('+ranges.length+' pages) x4='+x4});
    }catch(e){ send({t:'info',msg:'MAM enable err: '+e}); arming=false; }
  }});
  send({t:'info',msg:'slot16-watch installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
