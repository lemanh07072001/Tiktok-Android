'use strict';
// Locate the slot16 buffer's memory region (file-backed keystore vs heap) + bounded scan for copies.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null, active=0, inv=0, done=false;
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function isZero(hx){return !hx || /^0+$/.test(hx);}
function regionOf(p){try{const r=Process.findRangeByAddress(p);if(!r)return null;
  return {b:r.base.toString(),sz:r.size,prot:r.protection,file:r.file?r.file.path:null,foff:r.file?r.file.offset:null,off:p.sub(r.base).toString()};}catch(e){return null;}}
function boundedScan(hx){
  const bytes=[];for(let i=0;i<hx.length;i+=2)bytes.push(('0'+parseInt(hx.substr(i,2),16).toString(16)).slice(-2));
  const pat=bytes.join(' ');
  const ranges=Process.enumerateRanges('rw-').filter(r=>r.size<=32*1024*1024);
  send({t:'scanstart',n:ranges.length});
  let hits=0, budget=Date.now()+8000;
  for(const r of ranges){
    if(Date.now()>budget){send({t:'scanbudget'});break;}
    try{const res=Memory.scanSync(r.base,r.size,pat);
      for(const m of res){hits++;
        send({t:'HIT',addr:m.address.toString(),region:{b:r.base.toString(),sz:r.size,prot:r.protection,file:r.file?r.file.path:null,foff:r.file?r.file.offset:null,off:m.address.sub(r.base).toString()},around:h(m.address.sub(32),80)});
        if(hits>=12){send({t:'scancap'});return;}}
    }catch(e){}
  }
  send({t:'scandone',hits:hits});
}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1);if(sel!==369)return;active=1;this.mine=1;},
    onLeave(r){if(this.mine)active=0;}
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active||done)return; const len=u32(this.context.x1); if(len!==16)return;
      const hx=h(this.context.x0,16); if(isZero(hx))return;
      done=true; inv++;
      const x0=this.context.x0, x2=this.context.x2;
      send({t:'SLOT16',val:hx,
            x0:x0.toString(), x0region:regionOf(x0), x0wide:h(x0.sub(64),192),
            x2:x2.toString(), x2region:regionOf(x2),
            lr:this.context.lr.sub(base).toString()});
      setTimeout(()=>boundedScan(hx),200);
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',done:done}),4000);
