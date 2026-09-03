// _drv_ret.js — Reliable caller of the SM3-driver 0x9fdac via this.returnAddress (true LR), for slot16 calls.
// fp-walk was noisy (picked up SM3-compress code). returnAddress is guaranteed. Log it + P + val, plus x1..x7
// at entry so we can see which reg carried the slot16 ptr into 0x9fdac and disasm backward from the call-site.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=12;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); }catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(n>=MAX) return;
    const c=this.context; const x0=c.x0; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;                                  // slot16 hash only
    let v0=x0?peek(x0,16):null;
    if(!v0 || v0==='00000000000000000000000000000000') return;
    n++;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    // dump caller-relevant regs to spot who holds slot16-ptr / arena base
    const regs={};
    ['x0','x1','x2','x3','x4','x5','x6','x7','x19','x20','x21','x22','x23','x24','x25','fp','sp'].forEach(function(r){
      try{ regs[r]=c[r].toString(); }catch(e){} });
    send({t:'DRV', seq:n, tid:this.threadId, P:x0.toString(), val:v0,
          ret:off(ra), retRaw:ra?ra.toString():null, regs:regs});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n}); }, 5000);
