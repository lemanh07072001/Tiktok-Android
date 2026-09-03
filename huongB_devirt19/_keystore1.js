'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
const TOKEN='6c109094bc9ab89e050fbd3e2ca6b99e';
let base=null, scanned=false, sawToken=false;
function tob(hx){const a=new Uint8Array(hx.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(hx.substr(i*2,2),16);return a;}
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function modAt(p){ // which module/region contains p
  try{const m=Process.findRangeByAddress(p); if(!m)return null;
      const mod=Process.findModuleByName ? null:null;
      return {b:m.base.toString(),sz:m.size,prot:m.protection,file:m.file?m.file.path:null,
              foff:m.file?m.file.offset:null, off:p.sub(m.base).toString()};}catch(e){return null;}
}
function doScan(){
  if(scanned)return; scanned=true;
  const pat=Array.from(tob(TOKEN)).map(b=>('0'+b.toString(16)).slice(-2)).join(' ');
  const ranges=Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
  send({t:'scanstart',nranges:ranges.length});
  let hits=0;
  ranges.forEach(r=>{
    try{
      const res=Memory.scanSync(r.base, r.size, pat);
      res.forEach(m=>{
        hits++;
        send({t:'HIT',addr:m.address.toString(),
              region:{b:r.base.toString(),sz:r.size,prot:r.protection,
                      file:r.file?r.file.path:null,foff:r.file?r.file.offset:null,
                      off:m.address.sub(r.base).toString()},
              ctx:h(m.address.sub(48),96)});
      });
    }catch(e){}
  });
  send({t:'scandone',hits:hits});
}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;base=m.base;
  send({t:'info',base:base.toString()});
  // trigger scan shortly after first DRV that carries the token
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(sawToken)return; const len=u32(this.context.x1);
      if(len===16){const hx=h(this.context.x0,16); if(hx===TOKEN){sawToken=true;
        send({t:'tokenfed',x0:this.context.x0.toString(),lr:this.context.lr.sub(base).toString()});
        setTimeout(doScan,300);}}
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
// fallback scan even if token not seen via DRV
setTimeout(()=>{if(!scanned)doScan();},18000);
setInterval(()=>send({t:'mon',scanned:scanned,sawToken:sawToken}),4000);
