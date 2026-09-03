/*
 * _vm_trace13.js — PRODUCER WATCHPOINT (v13)
 *
 * At SM3-consume: grab buf B (holds slot16). Arm a HW WRITE watchpoint on B[0..15]
 * on the consuming thread, DO NOT stop the app. When slot16 is next (re)written,
 * the fault lands in setExceptionHandler => capture producer PC + backtrace + regs.
 *
 * Frida 17 API: thread.setHardwareWatchpoint(idx, addr, size, 'w'); thread from
 * Process.enumerateThreads(). Fault -> Process.setExceptionHandler.
 */
'use strict';
const SO='libmetasec_ov.so';
const SM3_DRV=0x9fdac;
let base=null,lo=null,hi=null;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }
function hexB(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }

let armed=false, bufAddr=null, watchThreadId=null, nFault=0;
const MAXFAULT=12;

Process.setExceptionHandler(function(d){
  try{
    if(!armed) return false;
    const pc = d.context.pc;
    const off = selfOff(pc);
    // capture regs of interest
    const c=d.context;
    const regs={};
    ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','lr','sp'].forEach(function(r){
      try{ regs[r]=c[r].toString(); }catch(e){}
    });
    let bt=[];
    try{ bt=Thread.backtrace(c, Backtracer.ACCURATE).map(selfOff); }catch(e){}
    const cur = bufAddr? hexB(bufAddr,16): null;
    send({t:'FAULT', n:nFault, type:d.type, pcOff:off, pcAbs:pc.toString(),
          memOp:(d.memory?{op:d.memory.operation, addr:d.memory.address.toString()}:null),
          bufNow:cur, regs:regs, bt:bt});
    nFault++;
    if(nFault>=MAXFAULT){ armed=false; }
    return true; // resume execution (step over)
  }catch(e){ try{send({t:'EH_ERR',e:String(e)});}catch(_){} return false; }
});

function armWatch(threadId){
  try{
    const ths=Process.enumerateThreads();
    let t=null;
    for(const x of ths){ if(x.id===threadId){ t=x; break; } }
    if(!t) t=ths[0];
    t.setHardwareWatchpoint(0, bufAddr, 16, 'w');
    watchThreadId=t.id;
    armed=true;
    send({t:'ARMED', buf:bufAddr.toString(), thread:t.id, wantThread:threadId, nThreads:ths.length});
  }catch(e){ send({t:'ARM_ERR', e:String(e)}); }
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'libmetasec loaded',base:base.toString()});
  Interceptor.attach(base.add(SM3_DRV),{
    onEnter(a){
      if(armed) return;
      const c=this.context;
      let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const B=c.x0; const V=hexB(B,16);
      if(!V || V==='00000000000000000000000000000000') return;
      bufAddr=ptr(B.toString());
      send({t:'SM3', slot16:V, buf:B.toString(), lr:selfOff(c.lr), ctxNbr:hexB(B.sub(32),96)});
      armWatch(this.threadId);
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,150); }; setTimeout(t,200); }
setInterval(function(){ send({t:'mon', armed:armed, nFault:nFault, watchThread:watchThreadId}); }, 5000);
