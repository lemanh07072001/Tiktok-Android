'use strict';
// _prod_url.js — capture FULL null-terminated x2 string (URL) paired with next slot16 same-thread
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null; const pending={}; let nPair=0; const MAX=10;
function cstr(p,max){ try{ let u=ptr(p); let s=''; for(let i=0;i<max;i++){ const b=u.add(i).readU8(); if(b===0) break; s+=('0'+b.toString(16)).slice(-2);} return s;}catch(e){return null;} }
function h(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(PROD),{ onEnter(a){ try{
    if((this.context.x1.toInt32()&0xffffffff)!==0x171) return;
    const tid=this.threadId, x2=this.context.x2;
    // x2 could itself be the char*, OR a std::string whose data ptr is at [x2].
    // capture BOTH: url_direct = cstr(x2); url_indirect = cstr([x2])
    let urlD=cstr(x2,600);
    let urlI=null; try{ const p=x2.readPointer(); urlI=cstr(p,600);}catch(e){}
    pending[tid]={urlD:urlD, urlI:urlI, x1:this.context.x1.toString()};
  }catch(e){} }});
  Interceptor.attach(base.add(DRV),{ onEnter(a){ try{
    const len=this.context.x1.toInt32()&0xffffffff; if(len!==16) return;
    const tid=this.threadId, val=h(this.context.x0,16);
    if(!val||/^0+$/.test(val)) return;
    const pend=pending[tid];
    if(pend && nPair<MAX){ nPair++; delete pending[tid];
      send({t:'U',slot16:val, urlD:pend.urlD, urlI:pend.urlI}); }
  }catch(e){} }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',nPair:nPair}),5000);
