'use strict';
const SO='libmetasec_ov.so'; const PROD=0x879d8;
let base=null; let n=0; const MAX=4000;
function hexN(p,k){ try{const u=new Uint8Array(ptr(p).readByteArray(k));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function dp(p){ try{return ptr(p).readPointer();}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(PROD),{ onEnter(a){ try{
    if(n>=MAX) return;
    const sel=this.context.x1.toInt32()&0xffffffff;
    const x2=this.context.x2;
    const at_x2=hexN(x2,16);
    const p1=dp(x2), at_p1=p1?hexN(p1,16):null;
    const p2=p1?dp(p1):null, at_p2=p2?hexN(p2,16):null;
    n++;
    send({t:'P',sel:sel,x2:at_x2,d1:at_p1,d2:at_p2});
  }catch(e){} }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',n:n}),4000);
