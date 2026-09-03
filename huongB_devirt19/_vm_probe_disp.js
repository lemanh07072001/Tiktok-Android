'use strict';
const SO='libmetasec_ov.so'; const DISP=0x55930; const SM3=0x9fdac;
let base=null,lo=null,hi=null;
let nDisp=0, nConsume=0, nNonzero=0, dispAtFirstNZ=-1;
function hexB(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(DISP),{ onEnter(a){ nDisp++; } });
  Interceptor.attach(base.add(SM3),{ onEnter(a){
    const c=this.context; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return; nConsume++;
    const V=hexB(c.x0,16);
    if(V && V!=='00000000000000000000000000000000'){ nNonzero++; if(dispAtFirstNZ<0) dispAtFirstNZ=nDisp; }
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,150); }; setTimeout(t,200); }
setInterval(function(){ send({t:'mon', nDisp:nDisp, nConsume:nConsume, nNonzero:nNonzero, dispAtFirstNZ:dispAtFirstNZ}); }, 3000);
