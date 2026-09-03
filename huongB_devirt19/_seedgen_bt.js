// _seedgen_bt.js — hook interp 0x52924, gate x0==base+0x18f430 (seed-gen program). At that point the
// call chain is: producer -> ... -> seed-gen wrapper 0x10ac2c -> interp. Backtrace reveals the PRODUCER
// (caller of seed-gen). Also gate on canonical-report window (nonzero-slot16 producing). Light hook.
'use strict';
const SO='libmetasec_ov.so', INTERP=0x52924, SEEDPROG=0x18f430;  // interp is hookable (like 0xa0748)
let base=null, n=0, seen={};
function relo(a){ try{ if(a && a.compare(base)>=0 && a.sub(base).compare(ptr(0x200000))<0) return '0x'+a.sub(base).toString(16); }catch(e){} return null; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(INTERP), { onEnter(a){
    try{
      if(!this.context.x0.equals(base.add(SEEDPROG))) return;   // only seed-gen program
      const fp=this.context.fp;              // = seed-gen wrapper 0x10ac2c fp (onEnter, before interp prologue)
      const chain=[]; let f=fp;
      for(let i=0;i<6;i++){ try{ const ret=relo(f.add(8).readPointer()); if(ret) chain.push(ret); f=f.readPointer(); if(f.isNull()) break; }catch(e){ break; } }
      const lr=relo(this.context.lr);
      const key=chain.slice(0,4).join(',');
      if(seen[key]) return; seen[key]=1; n++;
      send({t:'bt', n:n, lr:lr, chain:chain});
    }catch(e){ send({t:'err',msg:''+e}); }
  }});
  send({t:'info',msg:'seedgen-interp-bt installed @0x52924 gate 0x18f430'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const dl=Module.findGlobalExportByName('android_dlopen_ext');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}}); }
