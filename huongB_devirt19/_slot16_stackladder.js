// _slot16_stackladder.js — climb the call stack from the PROVEN slot16 reader up toward the producer.
// Trigger: the reliable reader = libmetasec-internal copy 0x172a50 with returnAddress==0xa0440 & size==16
//   (this is the tail memcpy of SM3_update copying the 16-byte slot16 message; fired 3x reliably before).
// At that instant the stack holds the return chain: SM3_update -> S-hash driver -> signing orchestrator
//   (which ASSEMBLED query/slot16 and wrote slot16 into a buffer). We PAC-safely scan the raw stack for
//   8-byte words landing inside libmetasec (=SELF return addresses) and report the ladder. Disassembling
//   backward from each SELF return address localizes the frame that produced slot16.
// Also capture: slot16 value, pool ptr P, and the caller's frame regs (x19..x28 from ctx) for provenance.
// SAFE: single low-volume Interceptor at 0x172a50, no Stalker, no libc/global hooks, no Thread.backtrace.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, done=false, nRd=0;
const MAX=10;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,k){try{return hx(p.readByteArray(k));}catch(e){return null;}}
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ return 'SELF+0x'+p.sub(base).toString(16); }
function tag(p){ return inSelf(p)?selfOff(p):(p?p.toString():'0'); }
// PAC-safe manual stack walk: scan sp..sp+WORDS*8 for values inside SO. Record slot index (frame depth proxy).
function scanStack(sp){
  const found=[]; const WORDS=160;
  for(let i=0;i<WORDS;i++){
    let v; try{ v=sp.add(i*8).readPointer(); }catch(e){ break; }
    if(inSelf(v)) found.push({slot:i, off:selfOff(v)});
    if(found.length>=24) break;
  }
  return found;
}
// snapshot callee-saved regs of the frame at the reader (they carry buffer/ctx pointers)
function regs(ctx){
  const out={};
  for(const r of ['x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp']){
    try{ out[r]=tag(ctx[r]); }catch(e){}
  }
  return out;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done)return;
    let dst,src,sz; try{ dst=args[0]; src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    const val=rh(src,16); if(!val) return;
    // require nonzero slot16 (skip all-zero warmups)
    if(val==='00000000000000000000000000000000') return;
    nRd++;
    const c=this.context;
    send({t:'rd', ord:nRd, tid:this.threadId, slot16:val, P:src.toString(),
          dst:dst.toString(), ladder:scanStack(c.sp), regs:regs(c)});
    if(nRd>=MAX){ done=true; send({t:'stopped', nRd:nRd}); }
  }});
  send({t:'armed', copy:'0x'+COPY.toString(16), reader:'0x'+READBUCKET.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
