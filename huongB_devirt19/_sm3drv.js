// _sm3drv.js — Confirm P is already-filled at the SM3 driver 0x9fdac, and capture the FULL input pair.
// 0x9fdac disasm: init(ctx=sp); SM3_update(ctx, data=inX0, len=inW1); SM3_update(ctx, data=inX2).
// => the reader's P (slot16 src) must be inX0 or inX2. Capture both buffers + len at ENTRY (before any update),
//    then the reader P/val, and correlate offline. If inX0/inX2 already == a later reader value at ENTRY,
//    the producer ran ABOVE 0x9fdac (as expected) -> next: bisect upward.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac, COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, nD=0, nR=0; const MAXD=20, MAXR=24;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(nD>=MAXD) return; nD++;
    const c=this.context;
    const x0=c.x0, x2=c.x2; let w1=null; try{ w1=c.x1.toUInt32?c.x1.toUInt32():parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    send({t:'DRV', seq:nD, tid:this.threadId,
          x0:x0?x0.toString():null, w1:w1,
          d0_16:x0?peek(x0,16):null, d0_32:x0?peek(x0,32):null,
          x2:x2?x2.toString():null, d2_16:x2?peek(x2,16):null, d2_32:x2?peek(x2,32):null});
  }});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(nR>=MAXR) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nR++;
    send({t:'RD', seq:nR, tid:this.threadId, P:src.toString(), val:val});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', nD:nD, nR:nR}); }, 5000);
