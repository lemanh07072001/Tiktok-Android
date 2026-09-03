// _arena_probe.js — Measure the marching-arena addressing so we can pick the right "catch-P-at-birth" strategy.
// Hook SM3-driver 0x9fdac, log every slot16 P (x0) address + value across an init/heartbeat burst.
// Offline we compute: stride between consecutive P (constant? => predict next P), address recurrence
// (ring/reuse? => arm WP on a seen P and wait), and the memory-range descriptor of the arena (heap? mmap?
// which tells us whether it's a malloc slot vs a bump region). Also log x2 (digest) to reconfirm stability.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=80;
let rangeLogged=false;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); }catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function rangeOf(p){
  try{ const r=Process.findRangeByAddress(p); if(!r) return null;
    return {b:r.base.toString(), sz:'0x'+r.size.toString(16), prot:r.protection,
            file:r.file?r.file.path:null, foff:r.file?('0x'+r.file.offset.toString(16)):null}; }
  catch(e){ return null; }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(n>=MAX) return;
    const c=this.context; const x0=c.x0; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;                                   // slot16-size hash only
    let v0=x0?peek(x0,16):null;
    if(!v0 || v0==='00000000000000000000000000000000') return;   // skip slot16=0 (feed traffic)
    n++;
    let rng=null;
    if(!rangeLogged){ rng=rangeOf(x0); rangeLogged=true; }        // characterize arena once
    send({t:'P', seq:n, tid:this.threadId, P:x0.toString(), val:v0,
          x2:c.x2?c.x2.toString():null, ret:off(this.returnAddress), rng:rng});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n}); }, 3000);
