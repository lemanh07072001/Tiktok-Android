// _regfile_emit.js — Hypothesis: the VM computes slot16 IN its register file (x1 slots) via ARX handlers, and
// P (the SM3-driver's x0) POINTS INTO that regfile (no copy => explains zero memcpy & zero idx7-to-P). So the
// "producer write to P" is a regfile-store handler `str x8,[x1,idx,lsl#3]` whose effective addr x1+idx*8 lands
// on P (P..P+8) or P+8 (P+8..P+16). We hook the 64-bit integer regfile-store handlers — incl. the ARX ops:
//   0xf04ac idx73 ROR (`ror w8,w9,w8; str x8,[x1,x10,lsl#3]`), 0xf09fc idx104 AND, 0xf0868 idx80 & 0xf0734 idx94
//   MOV (`str x8,[x1,x10,lsl#3]`), 0xf239c idx147 (`ldrsh; str x8,[x1,x9,lsl#3]`).
// The store value is in x8; the dest index in x10 (or x9 for idx147); regfile base = x1. We compute ea=x1+idx*8,
// keep a Map ea->{val,ip=*(x23) bytecode ptr, op, h}. At the SM3-driver (P holds slot16 V) we look up ea==P and
// ea==P+8 => the exact two VM instructions that wrote slot16's halves, with their bytecode pointers & opcodes.
// That pins the producer's emit tail; backward slice of the bytecode = the ARX. Map dedups by ea (bounded).
// Volume guard: gate safe 11s; mon shows per-handler counts — if a handler is too hot we narrow next run.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
// handler -> which context reg holds the dest index
const HANDLERS=[
  {off:0xf04ac, idxReg:'x10', op:'ror'},
  {off:0xf09fc, idxReg:'x10', op:'and'},
  {off:0xf0868, idxReg:'x10', op:'mov'},
  {off:0xf0734, idxReg:'x10', op:'mov2'},
  {off:0xf239c, idxReg:'x9',  op:'ldrsh'},
];
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=8;
const MAP=new Map(); const MAPMAX=200000; const cnt={};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function put(ea, rec){ if(MAP.size>MAPMAX){ MAP.clear(); } MAP.set(ea, rec); }
function hookRF(h){
  Interceptor.attach(base.add(h.off), { onEnter(a){ if(!safe) return; cnt[h.op]=(cnt[h.op]||0)+1; const c=this.context;
    let x1=c.x1, idx=null, val=null;
    try{ idx=parseInt(c[h.idxReg].toString()); }catch(e){ return; }
    try{ val=('0000000000000000'+c.x8.toString(16)).slice(-16); }catch(e){ return; }
    let ea=null; try{ ea=x1.add(idx*8); }catch(e){ return; }
    // record; ip (bytecode ptr) from x23 cell if available
    let ip=null; try{ ip=c.x23.readPointer(); }catch(e){}
    put(ea.toString(), {val:val, op:h.op, h:h.off, ip:ip?ip.toString():null,
                        ipOff:ip?selfOff(ip):null, opcode:(function(){try{return '0x'+(ip.readU32()&0x3f).toString(16);}catch(e){return null;}})()});
  }});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  HANDLERS.forEach(hookRF);
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek16(c.x0); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    const P=c.x0; const lo8=MAP.get(P.toString()); const hi8=MAP.get(P.add(8).toString());
    send({t:'DRV', drv:ndrv, V:V, P:P.toString(), loHalf:lo8||null, hiHalf:hi8||null, mapSize:MAP.size, cnt:cnt});
  }});
  send({t:'ready'}); return true;
}
function peek16(p){ try{ const u=new Uint8Array(p.readByteArray(16)); let s=''; for(let i=0;i<16;i++)s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 11000);
setInterval(function(){ send({t:'mon', safe:safe, ndrv:ndrv, mapSize:MAP.size, cnt:cnt}); }, 3000);
