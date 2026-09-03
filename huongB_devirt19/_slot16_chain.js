// _slot16_chain.js — cheap producer-localizer (no Stalker). Records every size-16 memcpy as
// {retoff, dst, src, val, ord}. When the a0440 read fires with a nonzero binary slot16 V, scans the
// ring backward for all copies carrying V -> reveals the chain producer-buffer -> ... -> arena -> consumer.
// The earliest-ordered copy of V whose src is not itself a prior dst = the origin (producer output buffer).
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, READOFF='a0440';
const CAP=8192;
let base=null, lo=null, hi=null, ord=0, reported=0;
const ring=[];  // {retoff,dst,src,val,ord}
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function isPrintableHeavy(v){let pr=0;for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16);if(c>=0x20&&c<=0x7e)pr++;}return pr>=12;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    const sz=args[2].toInt32(); if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0) return;
    const retoff=ra.sub(base).toString(16);
    let dst,src,val;
    try{ dst=args[0].toString(); src=args[1].toString(); val=hx(args[1].readByteArray(16)); }catch(e){ return; }
    const rec={retoff:retoff,dst:dst,src:src,val:val,ord:ord++};
    ring.push(rec); if(ring.length>CAP) ring.shift();
    // when the read-path consumes a nonzero binary slot16, trace its chain
    if(retoff===READOFF && val!=='00'.repeat(16) && !isPrintableHeavy(val) && reported<14){
      reported++;
      const same=ring.filter(r=>r.val===val).sort((a,b)=>a.ord-b.ord);
      // origin = earliest copy whose src is not the dst of any earlier same-value copy
      const dstsBefore={};
      let origin=null;
      for(const r of same){ if(!dstsBefore[r.src]){ origin=r; break; } dstsBefore[r.dst]=1; }
      // build compact chain view
      const chain=same.map(r=>({o:r.ord,retoff:r.retoff,src:r.src.slice(-10),dst:r.dst.slice(-10)}));
      send({t:'chain', val:val, nCopies:same.length,
            origin:{retoff:origin?origin.retoff:null, src:origin?origin.src:null},
            chain:chain});
    }
  }});
  send({t:'info',msg:'slot16-chain installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
