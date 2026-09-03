'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const A_HEX='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163';
let base=null, done=false;
function hexOf(p,n){ try{ const b=new Uint8Array(p.readByteArray(n)); let s='';
  for(let i=0;i<n;i++)s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function resolve(addr){
  try{ const m=Process.findModuleByAddress(addr);
    if(m) return {mod:m.name, off:'0x'+addr.sub(m.base).toString(16)};
    return {mod:null, abs:addr.toString()}; }
  catch(e){ return {err:''+e}; }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; send({t:'info',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(DRV),{ onEnter(a){
    if(done)return;
    const len=this.context.x1.toInt32()&0xffffffff;
    if(len<68)return;
    const pre=hexOf(this.context.x0,32);
    if(pre!==A_HEX)return;
    done=true;
    let bt=[];
    try{ bt=Thread.backtrace(this.context, Backtracer.FUZZY).map(resolve); }catch(e){ bt=[{err:''+e}]; }
    let btA=[];
    try{ btA=Thread.backtrace(this.context, Backtracer.ACCURATE).map(resolve); }catch(e){ btA=[{err:''+e}]; }
    send({t:'BT', len:len,
      lr:resolve(this.context.lr),
      x0:this.context.x0.toString(),
      fuzzy:bt, accurate:btA });
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO))install();
else { const t=()=>{ if(Process.findModuleByName(SO))install(); else setTimeout(t,200); }; setTimeout(t,400); }
setInterval(()=>send({t:'mon',done:done}),3000);
