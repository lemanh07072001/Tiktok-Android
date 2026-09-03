'use strict';
// _prod_io.js — capture producer(0x171) INPUT (x2 derefs) paired with the NEXT slot16 fed on same thread
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,lo=null,hi=null;
const pending={}; let nPair=0; const MAX=8;
function h(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function deref(p){ try{return ptr(p).readPointer();}catch(e){return null;} }

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){ try{
      if((this.context.x1.toInt32()&0xffffffff)!==0x171) return;
      const x2=this.context.x2, tid=this.threadId;
      const raw=h(x2,64);
      // interpret x2 as {ptr@0,len@8}
      const p0=deref(x2), len0=(()=>{try{return x2.add(8).readU32();}catch(e){return -1;}})();
      const d0=(p0&&len0>0&&len0<=4096)? h(p0,Math.min(len0,256)) : (p0? h(p0,64):null);
      const p10=deref(x2.add(0x10));
      const d10=p10? h(p10,64):null;
      pending[tid]={raw:raw, p0:''+p0, len0:len0, d0:d0, p10:''+p10, d10:d10};
    }catch(e){} }
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ try{
      const len=this.context.x1.toInt32()&0xffffffff;
      if(len!==16) return;
      const tid=this.threadId, val=h(this.context.x0,16);
      if(!val||/^0+$/.test(val)) return;
      const pend=pending[tid];
      if(pend && nPair<MAX){ nPair++; delete pending[tid];
        send({t:'PIO', slot16:val, in_raw:pend.raw, in_p0:pend.p0, in_len0:pend.len0, in_d0:pend.d0, in_p10:pend.p10, in_d10:pend.d10}); }
    }catch(e){} }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',nPair:nPair}),5000);
