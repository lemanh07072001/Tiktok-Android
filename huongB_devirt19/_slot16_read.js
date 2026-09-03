// _slot16_read.js — hook memcpy(0x172a50); for every size==16 copy whose return-address is inside
// libmetasec, read the 16 source bytes directly. Buckets by return-offset, samples distinct values.
// Directly captures the slot16 (arena->consumer copy) without any SM3 format assumption.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const buckets={};   // retoff -> {n, vals:Set(first 12)}
let base=null, lo=null, hi=null, tot16=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    const sz=args[2].toInt32(); if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0) return;
    const off=ra.sub(base).toString(16);
    let v; try{ v=hx(args[1].readByteArray(16)); }catch(e){ return; }
    tot16++;
    let b=buckets[off]; if(!b){ b={n:0, vals:[], set:{}}; buckets[off]=b; }
    b.n++;
    // count printable to distinguish ascii tails from binary slot16
    let pr=0; for(let i=0;i<32;i+=2){ const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++; }
    const nz = v!=='00'.repeat(16);
    if(nz && pr<12 && !b.set[v] && b.vals.length<12){ b.set[v]=1; b.vals.push(v); }
  }});
  send({t:'info',msg:'slot16-read installed base='+base});
  setInterval(function(){
    const rep={};
    for(const k in buckets){ rep[k]={n:buckets[k].n, binVals:buckets[k].vals}; }
    send({t:'buckets', tot16:tot16, data:rep});
  }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
