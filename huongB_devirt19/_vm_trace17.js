'use strict';
const SO='libmetasec_ov.so'; const DISP=0x55930; const SM3=0x9fdac;
let base=null,lo=null,hi=null;
const RING=900; const ring=new Array(RING); let ri=0, seq=0; let dumped=false;
function inHeap(p){ try{ const v=p; return v.compare(ptr('0x1000'))>0; }catch(e){return false;} }
function rd16(p){ try{ const u=new Uint8Array(p.readByteArray(16)); let s=''; for(let i=0;i<16;i++)s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(DISP),{ onEnter(a){
    if(dumped) return; const c=this.context;
    let op=null,bc=null; try{ const pcp=c.x23.readPointer(); bc=inSelf(pcp)?pcp.sub(base).toInt32():null; op=pcp.readU32()&0x3f; }catch(e){}
    // dump x0..x12 as {hex, mem16}
    const R={};
    const names=['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12'];
    for(const nm of names){ try{ const v=c[nm]; R[nm]=v.toString(); const mm=rd16(v); if(mm) R[nm+'m']=mm; }catch(e){} }
    ring[ri%RING]={s:seq++, op:op, bc:bc, R:R};
    ri++;
  }});
  Interceptor.attach(base.add(SM3),{ onEnter(a){
    if(dumped) return; const c=this.context; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;
    const V=rd16(c.x0); if(!V || V==='00000000000000000000000000000000') return;
    dumped=true;
    const P=c.x0.toString();
    const start=Math.max(0, ri-RING); const ents=[];
    for(let i=start;i<ri;i++){ const e=ring[i%RING]; if(e) ents.push(e); }
    send({t:'DUMP', slot16:V, P:P, total:ri, count:ents.length, ents:ents});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,120); }; setTimeout(t,150); }
setInterval(function(){ send({t:'mon', seq:seq, dumped:dumped}); }, 3000);
