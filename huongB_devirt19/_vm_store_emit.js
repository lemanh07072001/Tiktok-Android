// _vm_store_emit.js — Catch the VM instruction(s) that EMIT slot16 into P. The producer is VM bytecode; the
// 16 bytes are written to arena buffer P via the VM's memory-store handlers (not memcpy). From the dispatch
// table the store-to-pointer handlers are: idx7 0xf56c4 `str x10,[x8,x9]` (64b), idx4 0xf52fc `strh w9,[x8,x10]`,
// idx17 0xf50b8 `strb w10,[x8,x9]`. x8=base ptr, x9/x10=offset, value=x10/w9/w10. We hook each, filter to the
// arena band (cheap: ea=x8+off in 0x77e4…) to cut regfile-spill noise, and record {handler, ea, val, x23=VM-PC
// cell, instrPtr=*(x23), record bytes, x0}. The VM loop keeps the current instr ptr in x23 (`ldr x12,[x23]`),
// opcode=*(instrPtr)&0x3f. At the SM3-driver (P holds slot16 V) we match recorded stores whose ea∈[P,P+16) —
// those are the exact bytecode instructions that produced slot16 => the emit tail of the producer subprogram.
// Safe: 3 fixed point-hooks + band filter; gate after 9s (past ART cold-start). Counters expose hotness.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const H_STR=0xf56c4, H_STRH=0xf52fc, H_STRB=0xf50b8;
const BAND_LO=ptr('0x7000000000'), BAND_HI=ptr('0x8000000000'); // FIX: prior 0x77e4_00000000 had 2 extra 0s => P(0x77e4xxxxxx) never matched
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=8;
const STORES=[]; const SMAX=8000; const cnt={str:0,strh:0,strb:0,band:0};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function inBand(p){ try{ return p.compare(BAND_LO)>=0 && p.compare(BAND_HI)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function rec(handler, ea, valHex, c){
  let x23=c.x23, ipC=null, ip=null, recb=null;
  try{ ip=x23.readPointer(); ipC=selfOff(ip); recb=peek(ip,32);}catch(e){}
  STORES.push({h:handler, ea:ea.toString(), val:valHex,
               x23:x23?x23.toString():null, ip:ip?ip.toString():null, ipOff:ipC, rec:recb,
               op: (function(){try{return '0x'+(ip.readU32()&0x3f).toString(16);}catch(e){return null;}})(),
               x0:c.x0?c.x0.toString():null});
  if(STORES.length>SMAX) STORES.shift();
}
function hookStore(off, kind){
  Interceptor.attach(base.add(off), { onEnter(a){ if(!safe) return; cnt[kind]++; const c=this.context;
    let baseP=c.x8, off2=null, valHex=null, sz=8;
    try{
      if(kind==='str'){ off2=c.x9; valHex=('0000000000000000'+c.x10.toString(16)).slice(-16); sz=8; }
      else if(kind==='strh'){ off2=c.x10; valHex=('0000'+(parseInt(c.x9.toString())&0xffff).toString(16)).slice(-4); sz=2; }
      else { off2=c.x9; valHex=('00'+(parseInt(c.x10.toString())&0xff).toString(16)).slice(-2); sz=1; }
    }catch(e){ return; }
    let ea=null; try{ ea=baseP.add(off2); }catch(e){ return; }
    if(!inBand(ea)) return; cnt.band++;
    rec(off, ea, valHex, c);
  }});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  hookStore(H_STR,'str'); hookStore(H_STRH,'strh'); hookStore(H_STRB,'strb');
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    const P=c.x0, Plo=P, Phi=P.add(16);
    const hits=[]; for(let i=STORES.length-1;i>=0 && hits.length<40;i--){ const s=STORES[i];
      let ea=null; try{ ea=ptr(s.ea);}catch(e){continue;}
      if(ea.compare(Plo)>=0 && ea.compare(Phi)<0) hits.push(s);
    }
    send({t:'DRV', drv:ndrv, V:V, P:P.toString(), emitHits:hits, nStores:STORES.length, cnt:cnt});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 9000);
setInterval(function(){ send({t:'mon', safe:safe, ndrv:ndrv, nStores:STORES.length, cnt:cnt}); }, 3000);
