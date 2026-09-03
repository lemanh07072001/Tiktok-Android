// _rd_bt.js (v2) — REAL producer chain at the reader via a BOUNDED frame-pointer walk (no Thread.backtrace,
// which hangs on this OLLVM code). ARM64 frame chain: x29 -> [saved_x29, saved_x30]. Walk it, strip PAC,
// map each saved-LR to SELF+off. The stable SELF frames above 0xa0440 are the real producer call-chain.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, n=0; const MAX=6;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function strip(p){ try{ return ptr('0x'+uint64(p.toString()).and(uint64('0x0000007fffffffff')).toString(16)); }catch(e){ return p; } }
function fpwalk(ctx){
  const frames=[];
  let fp=null; try{ fp=ctx.fp; }catch(e){}
  let prev=null;
  for(let i=0;i<14 && fp && !fp.isNull();i++){
    let sfp=null, slr=null;
    try{ sfp=fp.readPointer(); slr=fp.add(8).readPointer(); }catch(e){ break; }
    const lr=strip(slr);
    frames.push({lr:off(lr), raw:slr.toString(), inSelf:inSelf(lr)});
    if(prev && sfp.compare(fp)<=0) break;         // must climb
    prev=fp; fp=sfp;
  }
  return frames;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(n>=MAX) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    n++;
    let x19=null; try{ x19=this.context.x19.toString(); }catch(e){}
    send({t:'RD', ord:n, tid:this.threadId, P:src.toString(), x19:x19, val:val, ra:off(ra), frames:fpwalk(this.context)});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ if(n<MAX) send({t:'mon', n:n}); }, 5000);
