// _bt_driver.js — Cheap/safe: at the SM3 driver (x0=P holds slot16, w1=16), capture the CALL CHAIN.
// slot16 is already in x0, so whatever assembled it and is now calling the driver is on the stack. Resolve
// ACCURATE + FUZZY backtraces to SELF+off / module+off; also scan the top of the stack for pointers that hold
// the slot16 value (find the source buffer) and for SELF code pointers (return addresses the unwinder missed).
// Goal: name the immediate non-thunk caller = the function that produced/fetched slot16 => the producer lead.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=6;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function lbl(p){ return selfOff(p)||modOff(p); }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(n>=MAX) return; const c=this.context; const P=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const v0=peek(P,16); if(!v0||v0==='00000000000000000000000000000000') return; n++;
    let acc=[],fuz=[];
    try{ acc=Thread.backtrace(c, Backtracer.ACCURATE).map(lbl); }catch(e){}
    try{ fuz=Thread.backtrace(c, Backtracer.FUZZY).map(lbl); }catch(e){}
    // scan stack: find slot pointers holding v0, and SELF code ptrs
    const sp=c.sp; const selfPtrs=[]; const valPtrs=[];
    for(let off=0; off<0x400; off+=8){ let q=null; try{ q=sp.add(off).readPointer(); }catch(e){ break; }
      const so=selfPtrs.length<24?selfOff(q):null; if(so) selfPtrs.push([off,so]);
      // does q point to a 16-byte region equal to v0?
      if(valPtrs.length<6){ try{ const vv=peek(q,16); if(vv===v0) valPtrs.push([off,q.toString()]); }catch(e){} }
    }
    send({t:'BT', n:n, P:P.toString(), val:v0, x1:c.x1.toString(), x2:c.x2.toString(),
          lr:lbl(c.lr), acc:acc.slice(0,12), fuz:fuz.slice(0,14), selfPtrs:selfPtrs.slice(0,16), valPtrs:valPtrs});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n}); }, 3000);
