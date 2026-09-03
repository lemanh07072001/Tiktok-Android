// _wp_reuse.js — Producer hunt v3: arm the (proven-stable) HW write-WP directly on the REAL slot16 buffer P,
// as identified at the SM3 driver 0x9fdac (x0=P already holds slot16, w1=16). The WP catches the NEXT write
// into P. Hypothesis: the slot16 buffer is pooled/reused, so the next writer re-filling P for a later request
// IS the producer. We tally next-writer PCs + the 16 bytes they leave, flag any store from inside libmetasec,
// and flag any value that looks like a slot16 (16 non-ASCII, high-entropy) vs an ASCII header string.
// One WP slot (0). Arm on a fresh P when the slot is free; disarm on catch; re-arm on the next driver hit.
// Gate arming until 15s (avoid ART cold-start churn). Exception handler alone proven safe (segv passthrough).
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, anchorBase=null;
let safe=false, hot=false, win=null;
let armed=false, curP=null, curArmVal=null, arms=0, caps=0, done=false; const MAXC=60;
const pcTally={};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function isAscii(hexstr){ if(!hexstr) return false; for(let i=0;i<hexstr.length;i+=2){ const b=parseInt(hexstr.substr(i,2),16); if(b!==0 && (b<0x20||b>0x7e)) return false; } return true; }
function inWin(p){ try{ return win && p.compare(win.lo)>=0 && p.compare(win.hi)<0; }catch(e){ return false; } }
function disarm(){ if(!armed) return; try{ Process.enumerateThreads().forEach(function(t){ try{t.unsetHardwareWatchpoint(0);}catch(e){} }); }catch(e){} armed=false; curP=null; curArmVal=null; }
function setHandler(){
  Process.setExceptionHandler(function(d){
    if(d.type==='access-violation') return false;
    if(d.type!=='breakpoint' && d.type!=='single-step') return false;
    let pc=null; try{ pc=d.context.pc; }catch(e){} if(!pc) return false;
    const inLib=inSelf(pc); const key=selfOff(pc);
    const valAfter=curP?peek(curP,16):null; const ascii=isAscii(valAfter);
    pcTally[key]=(pcTally[key]||0)+1;
    const c=d.context; const regs={};
    ['x0','x1','x2','x3','x8','x9','x10','x11','x12','x13','x14','x19','x20','x21','x22','fp'].forEach(function(r){ try{ regs[r]=c[r].toString(); }catch(e){} });
    let lr=null; try{ lr=selfOff(c.lr); }catch(e){}
    send({t:'HIT', cap:++caps, pc:key, pcMod:modOff(pc), inLib:inLib, P:curP?curP.toString():null,
          armVal:curArmVal, valAfter:valAfter, ascii:ascii, slot16like:(!ascii && valAfter && valAfter!=='00000000000000000000000000000000'),
          lr:lr, regs:regs});
    disarm(); if(caps>=MAXC) done=true; return true;
  });
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  setHandler();
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(done||!safe) return; const c=this.context; const P=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const v0=peek(P,16); if(!v0||v0==='00000000000000000000000000000000') return;
    if(!win){ const w=P.and(ptr('0xFFFFFFFFF0000000')); win={lo:w, hi:w.add(ptr('0x10000000'))}; hot=true; send({t:'win', firstP:P.toString()}); }
    if(armed) return;                       // WP slot busy; skip until it catches or is cleared
    const tid=this.threadId; const th=Process.enumerateThreads().find(function(t){return t.id===tid;}); if(!th) return;
    try{ th.setHardwareWatchpoint(0, P, 8, 'w'); armed=true; curP=P; curArmVal=v0; arms++; if(arms<=3) send({t:'armed', P:P.toString(), val:v0, tid:tid}); }
    catch(e){ if(arms<3) send({t:'arm_err', e:String(e)}); }
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 15000);
setInterval(function(){
  const top=Object.keys(pcTally).map(function(k){return [k,pcTally[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,8);
  send({t:'mon', safe:safe, hot:hot, arms:arms, caps:caps, armed:armed, top:top});
}, 3000);
