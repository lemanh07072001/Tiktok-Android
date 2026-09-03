// _wp_tag.js v2 — Catch the INLINE producer store via HW watchpoint, anchored at the 0x14fda4 memcpy return.
// v1 died from app-wide memcpy hook overhead while hot (+ the ~60/sec ART SIGSEGV baseline through the handler).
// Fix: instead of hooking libc memcpy for every call, attach directly at SELF+0x14fda4 (the instruction right
// after `bl memcpy`). Per AAPCS memcpy returns dst in x0, so at 0x14fda4 x0 = D (the 16B slot just filled with
// "x-tt-request-tag"). This site runs ONLY during signing => negligible overhead. Arm an 8-byte write WP on D;
// the next store into D is the producer's inline slot16 write => the WP delivers its exact PC + regs.
// Gates: exception handler + anchor attach install lazily, only after an 15s cold-start gate (ART startup uses
// SIGSEGV heavily; the handler is fine steady-state but we still avoid arming during startup churn).
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const ANCHOR=0x14fda4;
let base=null, lo=null, hi=null, anchorAddr=null;
let hot=false, safe=false, win=null;
let armed=false, curD=null, caps=0, arms=0, done=false, nAnchor=0; const MAXC=30;
const pcTally={};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function inWin(p){ try{ return win && p.compare(win.lo)>=0 && p.compare(win.hi)<0; }catch(e){ return false; } }
function disarm(){ if(!armed) return; try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){} armed=false; curD=null; }
function setHandler(){
  Process.setExceptionHandler(function(d){
    if(d.type==='access-violation') return false;
    if(d.type!=='breakpoint' && d.type!=='single-step') return false;
    let pc=null; try{ pc=d.context.pc; }catch(e){} if(!pc) return false;
    const inLib=inSelf(pc); const key=selfOff(pc); const val=curD?peek(curD,16):null;
    pcTally[key]=(pcTally[key]||0)+1;
    const c=d.context; const regs={};
    ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x19','x20','x21','x22','x23','x24','x25','fp'].forEach(function(r){ try{ regs[r]=c[r].toString(); }catch(e){} });
    let lr=null; try{ lr=selfOff(c.lr); }catch(e){}
    send({t:'HIT', cap:++caps, pc:key, pcMod:modOff(pc), inLib:inLib, D:curD?curD.toString():null, valNow:val, lr:lr, regs:regs});
    disarm(); if(caps>=MAXC) done=true; return true;
  });
}
function goHot(firstP){ if(hot) return; hot=true;
  const w=firstP.and(ptr('0xFFFFFFFFF0000000')); win={lo:w, hi:w.add(ptr('0x10000000'))};
  setHandler();
  Interceptor.attach(anchorAddr, { onEnter(args){
    if(done||armed) return; const D=this.context.x0; if(!D||!inWin(D)) return; nAnchor++;
    const tid=this.threadId; const th=Process.enumerateThreads().find(function(t){return t.id===tid;}); if(!th) return;
    try{ th.setHardwareWatchpoint(0, D, 8, 'w'); armed=true; curD=D; arms++; if(arms<=3) send({t:'armed', D:D.toString(), tid:tid}); }
    catch(e){ if(arms<3) send({t:'arm_err', e:String(e)}); }
  }});
  send({t:'HOT', win:win.lo.toString()+'..'+win.hi.toString(), firstP:firstP.toString()});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); anchorAddr=base.add(ANCHOR);
  send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(hot||!safe) return; const c=this.context; const x0=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    let v0=peek(x0,16); if(!v0||v0==='00000000000000000000000000000000') return; goHot(x0); }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 15000);
setInterval(function(){
  const top=Object.keys(pcTally).map(function(k){return [k,pcTally[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,6);
  send({t:'mon', safe:safe, hot:hot, arms:arms, caps:caps, armed:armed, nAnchor:nAnchor, top:top});
}, 3000);
