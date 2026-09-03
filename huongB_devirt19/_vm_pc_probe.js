// _vm_pc_probe.js — DECISIVE test: is slot16 produced by the VM interpreter (0x55950, ctx 0x52924),
// and is its bytecode STATIC (in libmetasec => fully offline-liftable) or runtime heap (dump-once)?
//
// Mechanism proven safe: hook ONLY the SM3-driver 0x9fdac (x0=P holds slot16, w1=16). At that moment the
// VM loop frame is (claimed) still on the stack, and x23 (callee-saved) should hold the VM-PC CELL pointer
// (`str x8,[x23]` at 0x558b4 => *(x23) = current VM instruction record ptr). We:
//   1. read x23, *(x23)=instrPtr; classify: libmetasec(static bytecode) / heap / other / garbage.
//   2. dump a u32 window around instrPtr with opcode=word&0x3f decode (the flat-u32 threaded program).
//   3. read x30 (context key; expect 0x52924 if this is the VM) and x24/x1 (regfile candidates); search the
//      regfile area for the 16-byte slot16 value to locate its slot.
//   4. scan the stack for SELF return addresses to reconfirm the call chain (…0x55950 escape, 0xa103c thunk).
// Cheap: driver hook + reads on trigger only. Gate safe after 12s (avoid ART cold-start churn).
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, safe=false, n=0; const MAX=8;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function cls(p){ // classify a pointer
  try{ if(p.isNull()) return 'null'; }catch(e){ return 'bad'; }
  const s=selfOff(p); if(s) return s;
  try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(p); if(r) return '['+r.protection+' '+r.base+'+0x'+p.sub(r.base).toString(16)+' sz0x'+r.size.toString(16)+']'; }catch(e){}
  return p.toString();
}
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function u32win(p, before, after){ // dump u32 words from p-before*4 .. p+after*4 with opcode decode
  const rows=[];
  for(let i=-before;i<after;i++){ try{ const a=p.add(i*4); const w=a.readU32();
    rows.push({o:i*4, w:'0x'+w.toString(16), op:'0x'+(w&0x3f).toString(16)});
  }catch(e){ rows.push({o:i*4, w:'?'}); break; } }
  return rows;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||n>=MAX) return; const c=this.context;
    const P=c.x0; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const v0=peek(P,16); if(!v0||v0==='00000000000000000000000000000000') return; n++;
    // --- x23 = VM-PC cell? ---
    const x23=c.x23; let vmPCcell=null, instrPtr=null, instrCls=null, win=null;
    try{ vmPCcell=x23.toString(); instrPtr=x23.readPointer(); instrCls=cls(instrPtr); win=u32win(instrPtr,8,24); }catch(e){ instrCls='x23-deref-fail:'+e; }
    // --- x30 context key + regfile candidates ---
    const x30=c.x30?c.x30.toString():null;
    // search regfile candidates (x24, x1) for the slot16 value + nearby ptr targets
    function scanRF(reg,label){ const out={reg:label, val:reg?reg.toString():null, cls:reg?cls(reg):null, foundSlotAt:null, slots:[]};
      if(!reg) return out;
      try{ for(let i=0;i<48;i++){ const cell=reg.add(i*8); let q=null; try{ q=cell.readPointer(); }catch(e){ break; }
        // direct 16B match at cell?
        let d=null; try{ d=peek(cell,16); }catch(e){}
        if(d===v0 && out.foundSlotAt===null) out.foundSlotAt='cell#'+i+' (inline)';
        // pointer to a buffer holding v0?
        let pd=null; try{ pd=peek(q,16); }catch(e){}
        if(pd===v0 && out.foundSlotAt===null) out.foundSlotAt='cell#'+i+' -> '+q.toString();
        if(i<8) out.slots.push({i:i, q:q.toString(), qcls:cls(q)});
      } }catch(e){}
      return out;
    }
    const rfX24=scanRF(c.x24,'x24'); const rfX1=scanRF(c.x1,'x1'); const rfX20=scanRF(c.x20,'x20');
    // --- stack scan for SELF return addrs ---
    const sp=c.sp; const selfPtrs=[];
    for(let off=0;off<0x400;off+=8){ let q=null; try{ q=sp.add(off).readPointer(); }catch(e){ break; }
      const so=selfOff(q); if(so && selfPtrs.length<20) selfPtrs.push([off,so]); }
    send({t:'HIT', n:n, P:P.toString(), val:v0, digestCtx:cls(c.x2),
          x23:vmPCcell, instrPtr:instrPtr?instrPtr.toString():null, instrCls:instrCls, win:win,
          x30:x30, x30cls:c.x30?cls(c.x30):null,
          rf:{x24:rfX24, x1:rfX1, x20:rfX20}, selfPtrs:selfPtrs });
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 12000);
setInterval(function(){ send({t:'mon', n:n, safe:safe}); }, 3000);
