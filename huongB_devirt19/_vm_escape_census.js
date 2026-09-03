// _vm_escape_census.js — Decisive direction test: during the slot16 producer window, is the VM even running,
// and which NATIVE functions does it dispatch? VM native-escape is `0x5594c blr x8` (x8=native fn, x0=arg). We
// hook 0x5594c (fires once per native dispatch — moderate rate, not per-opcode) and ring-record {fn=x8 classified,
// arg=x0, arg first-32B}. Also hook the VM core loop head 0x55834 with a cheap counter (sampled) to gauge VM
// activity. At the SM3-driver (P holds slot16 V) we report: VM-iters seen, distinct native fns dispatched
// recently (beyond the known SM3 0x9fd18 / base64 0x10b940 0x10baa8), and whether any recent dispatch arg is P
// or contains V. A NEW native fn dispatched just before the driver = the slot16 producer candidate. If the VM
// core counter stays ~0 through the burst => producer is native code OUTSIDE this VM => redirect. Safe: 2 point
// hooks; the loop-head counter is a bare increment. Gate safe 8s (catch early bursts too).
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac, ESC=0x5594c, LOOP=0x55834;
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=8;
let vmIters=0; const RING=[]; const RMAX=3000;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function cls(p){ try{ if(p.isNull()) return 'null'; }catch(e){ return 'bad'; }
  const s=selfOff(p); if(s) return s;
  try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16); }catch(e){}
  return p.toString(); }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(LOOP), { onEnter(){ if(safe) vmIters++; } });
  Interceptor.attach(base.add(ESC), { onEnter(){ if(!safe) return; const c=this.context;
    const fn=c.x8, arg=c.x0;
    RING.push({it:vmIters, fn:fn?cls(fn):null, arg:arg?arg.toString():null, argb:arg?peek(arg,32):null});
    if(RING.length>RMAX) RING.shift();
  }});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    const P=c.x0.toString();
    // distinct fns in ring, plus any dispatch whose arg==P or argb contains V
    const freq={}; const pHits=[]; const vHits=[];
    for(let i=RING.length-1;i>=0;i--){ const r=RING[i]; freq[r.fn]=(freq[r.fn]||0)+1;
      if(r.arg===P) pHits.push(r);
      if(r.argb && r.argb.indexOf(V)>=0) vHits.push(r);
    }
    const distinct=Object.keys(freq).map(function(k){return [k,freq[k]];}).sort(function(a,b){return b[1]-a[1];});
    send({t:'DRV', drv:ndrv, V:V, P:P, vmIters:vmIters, ringLen:RING.length,
          distinctFns:distinct.slice(0,16), argEqualsP:pHits.slice(0,4), argHasV:vHits.slice(0,4)});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 8000);
setInterval(function(){ send({t:'mon', safe:safe, ndrv:ndrv, vmIters:vmIters, ringLen:RING.length}); }, 3000);
