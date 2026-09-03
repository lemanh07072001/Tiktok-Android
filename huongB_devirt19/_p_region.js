'use strict';
const SO='libmetasec_ov.so'; const SM3=0x9fdac;
let base=null,lo=null,hi=null,done=false;
function rd16(p){ try{ const u=new Uint8Array(p.readByteArray(16)); let s=''; for(let i=0;i<16;i++)s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(SM3),{ onEnter(a){
    if(done) return; const c=this.context; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;
    const V=rd16(c.x0); if(!V||V==='00000000000000000000000000000000') return;
    done=true;
    const P=c.x0;
    let reg=null; try{ reg=Process.findRangeByAddress(P); }catch(e){}
    let out={t:'REGION', slot16:V, P:P.toString()};
    if(reg){ out.base=reg.base.toString(); out.size=reg.size; out.prot=reg.protection; out.file=reg.file?reg.file.path:null; out.offInRegion='0x'+P.sub(reg.base).toString(16); }
    // neighbor ranges: list ranges around P (prev/this/next)
    try{
      const rs=Process.enumerateRanges('---'); // all
      let idx=-1;
      for(let i=0;i<rs.length;i++){ if(P.compare(rs[i].base)>=0 && P.compare(rs[i].base.add(rs[i].size))<0){ idx=i; break; } }
      const nb=[];
      for(let j=Math.max(0,idx-2); j<=Math.min(rs.length-1,idx+2) && idx>=0; j++){
        nb.push({base:rs[j].base.toString(), size:rs[j].size, prot:rs[j].protection, file:rs[j].file?rs[j].file.path:null});
      }
      out.neighbors=nb;
    }catch(e){ out.nbErr=String(e); }
    // dump 64B around P
    try{ out.win=(function(){const u=new Uint8Array(P.sub(16).readByteArray(96));let s='';for(let i=0;i<96;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;})(); }catch(e){}
    send(out);
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,120); }; setTimeout(t,150); }
setInterval(function(){ send({t:'mon', done:done}); }, 3000);
