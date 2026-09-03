'use strict';
const SO='libmetasec_ov.so'; const DISP=0x55930; const SM3=0x9fdac;
let base=null,lo=null,hi=null;
const RING=4096; const ring=new Array(RING); let ri=0, seq=0; let dumped=false;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ return p.sub(base).toInt32(); }catch(e){ return null; } }
function hexB(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(DISP),{ onEnter(a){
    if(dumped) return;
    const c=this.context;
    // raw x15 target (handler) + opcode via *x23 model + x20 (table base?) 
    let x15o=null, inS=false, op=null, bc=null;
    try{ const x15=c.x15; inS=inSelf(x15); x15o = inS? x15.sub(base).toInt32() : ('EXT:'+x15.toString()); }catch(e){}
    try{ const pcp=c.x23.readPointer(); bc=inSelf(pcp)?pcp.sub(base).toInt32():null; op=pcp.readU32()&0x3f; }catch(e){}
    ring[ri%RING]={s:seq++, h:x15o, in:inS, op:op, bc:bc};
    ri++;
  }});
  Interceptor.attach(base.add(SM3),{ onEnter(a){
    if(dumped) return;
    const c=this.context; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;
    const V=hexB(c.x0,16);
    if(!V || V==='00000000000000000000000000000000') return;
    dumped=true;
    const start=Math.max(0, ri-RING); const ents=[];
    for(let i=start;i<ri;i++){ const e=ring[i%RING]; if(e) ents.push(e); }
    send({t:'DUMP', slot16:V, total:ri, count:ents.length, ents:ents});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,120); }; setTimeout(t,150); }
setInterval(function(){ send({t:'mon', seq:seq, dumped:dumped}); }, 3000);
