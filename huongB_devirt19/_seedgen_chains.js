// _seedgen_chains.js — gate interp 0x52924 on x0==seed-gen program 0x18f430; for each call walk the
// fp-chain (light: read [fp],[fp+8] a few levels, NO Backtracer) → the caller context. Dedup by chain.
// The slot16-PRODUCER's seed-gen call has a chain that does NOT go through serialize (0x8e2e8/0x8e304).
'use strict';
const SO='libmetasec_ov.so', INTERP=0x52924, SEEDPROG=0x18f430;
let base=null, n=0; const seen={};
function relo(a){ try{ if(a && a.compare(base)>=0 && a.sub(base).compare(ptr(0x200000))<0) return '0x'+a.sub(base).toString(16); }catch(e){} return null; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(INTERP), { onEnter(){
    try{
      if(!this.context.x0.equals(base.add(SEEDPROG))) return;
      let f=this.context.fp; const chain=[];
      for(let i=0;i<7 && !f.isNull();i++){
        let ret=null,nf=null;
        try{ ret=relo(f.add(8).readPointer()); nf=f.readPointer(); }catch(e){ break; }
        if(ret) chain.push(ret);
        if(nf.compare(f)<=0) break; f=nf;
      }
      const key=chain.slice(0,5).join(',');
      if(seen[key]) return; seen[key]=1; n++;
      send({t:'chain', n:n, chain:chain});
      if(n>=40){ /* enough */ }
    }catch(e){}
  }});
  send({t:'info',msg:'seedgen-chains installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
