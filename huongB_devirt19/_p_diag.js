'use strict';
const SO='libmetasec_ov.so', INVOKER=0xa1004, SM3_DRV=0x9fdac;
let base=null,lo=null,hi=null; let nInv=0,nSm3=0; const objseen={};
function ioff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return p.sub(base).toInt32(); }catch(e){} return -1; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info',msg:'base='+base});
  // direct SM3 driver (confirm burst)
  Interceptor.attach(base.add(SM3_DRV),{ onEnter(){ let w1=-1; try{w1=parseInt(this.context.x1.toString())&0xffffffff;}catch(e){}
    if(w1===16){ nSm3++; if(nSm3<=3) send({t:'sm3',n:nSm3,lr:ioff(this.context.lr)}); } } });
  // invoker, NO filter: count + record obj[0] offset distribution
  try{
    Interceptor.attach(base.add(INVOKER),{ onEnter(){ nInv++;
      try{ const fn=this.context.x0.readPointer(); const fo=ioff(fn); objseen[fo]=(objseen[fo]||0)+1; }catch(e){} } });
    send({t:'info',msg:'invoker hook ok'});
  }catch(e){ send({t:'info',msg:'invoker hook FAIL '+e}); }
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>{ // report top obj[0] offsets
  const top=Object.keys(objseen).map(k=>[k,objseen[k]]).sort((a,b)=>b[1]-a[1]).slice(0,6);
  send({t:'mon',nInv:nInv,nSm3:nSm3,top:top});
},4000);
