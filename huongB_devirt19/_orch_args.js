// _orch_args.js — Is the slot16 buffer P derivable from the orchestrator's args (esp. x8 struct-return)?
// Hook 0x94d08 entry (the fn enclosing 0x95a9c). Dump x0,x1,x8 (+ 32 bytes each). Hook reader -> P,val.
// Correlate offline: if every P lies within [x8, x8+N] or [x0, x0+N], we can compute P at orch-entry and
// arm the proven 8-byte WP BEFORE the producer writes it -> trap the producer store PC.
'use strict';
const SO='libmetasec_ov.so';
const ORCH=0x94d08, COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, seq=0, nO=0, nR=0; const MAXO=12, MAXR=24;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(ORCH), { onEnter(args){
    if(nO>=MAXO) return; nO++; const s=++seq;
    function r(name){ try{ return this.context[name]; }catch(e){ return null; } }
    const c=this.context;
    const x0=c.x0, x1=c.x1, x8=c.x8;
    send({t:'ORCH', seq:s, tid:this.threadId,
          x0:x0?x0.toString():null, x1:x1?x1.toString():null, x8:x8?x8.toString():null,
          m_x0:x0?peek(x0,32):null, m_x8:x8?peek(x8,32):null});
  }});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(nR>=MAXR) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nR++; const s=++seq;
    send({t:'RD', seq:s, tid:this.threadId, P:src.toString(), val:val});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', nO:nO, nR:nR}); }, 5000);
