'use strict';
const SO='libmetasec_ov.so'; const SM3_DRV=0x9fdac;
let base=null,lo=null,hi=null;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }
function hexB(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
let n=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(SM3_DRV),{
    onEnter(a){
      const c=this.context;
      let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const B=c.x0; const V=hexB(B,16);
      send({t:'C', i:n++, slot16:V, buf:B.toString(), lr:selfOff(c.lr), tid:this.threadId});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,150); }; setTimeout(t,200); }
setInterval(function(){ send({t:'mon', n:n}); }, 5000);
