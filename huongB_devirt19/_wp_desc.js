// _wp_desc.js — Catch the COMMAND-BUILDER (and thus reach the producer) via a stable-address watchpoint.
// Proven: slot16 SM3 command is dispatched by thunk 0xa1004 from a descriptor {fn, P, len, digest, ret}.
// The descriptor sits at a STABLE address (x19 at 0x9fdac entry, e.g. 0x75c67991b0); field [+8]=P (marching).
// Whoever writes [desc+8]=P is the builder, running right AFTER the producer wrote slot16 into P.
// Plan: at the FIRST slot16 call, read desc=x19, arm an 8-byte WRITE watchpoint on desc+8 (STABLE -> no arena
// problem). Next cycle's builder store into desc+8 traps -> handler logs the store PC + regs. Disasm backward
// from that PC offline to find the producer bl.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, armed=false, armAddr=null, nBP=0, nD=0, done=false;
function selfOff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation') return false;
  if(d.type!=='breakpoint' && d.type!=='single-step') return false;
  nBP++;
  const c=d.context; let pc=null; try{ pc=c.pc; }catch(e){}
  let mem=null,op=null; try{ if(d.memory){ mem=d.memory.address?d.memory.address.toString():null; op=d.memory.operation; } }catch(e){}
  const regs={};
  ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x19','x20','x21','x22','x23','x24','fp','lr','sp'].forEach(function(r){
    try{ regs[r]=c[r].toString(); }catch(e){} });
  // read 16 bytes at the pointer being stored (if a reg holds a marching arena ptr, dump it)
  const arenaDump={};
  ['x0','x1','x2','x8','x9','x19','x20','x21'].forEach(function(r){
    try{ const v=c[r]; if(v && v.toString().indexOf('0x77e4')===0) arenaDump[r]=peek(v,16); }catch(e){} });
  send({t:'BP', n:nBP, pc:pc?selfOff(pc):null, pcRaw:pc?pc.toString():null, inSelf:pc?inSelf(pc):false,
        mem:mem, op:op, armAddr:armAddr, regs:regs, arenaDump:arenaDump});
  try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){}
  armed=false; done=true;
  return true;
});
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(done) return;
    const c=this.context; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;
    let x0=c.x0; let v0=x0?peek(x0,16):null;
    if(!v0 || v0==='00000000000000000000000000000000') return;
    nD++;
    const desc=c.x19;                       // descriptor base (x19 at entry = caller thunk's x19)
    send({t:'DRV', seq:nD, tid:this.threadId, P:x0.toString(), val:v0, desc:desc?desc.toString():null, x2:c.x2.toString()});
    if(nD>=1 && !armed && desc){
      const target=desc.add(8);             // desc+8 = P slot (STABLE address)
      const tid=this.threadId;
      const th=Process.enumerateThreads().find(function(t){return t.id===tid;});
      if(th){
        try{ th.setHardwareWatchpoint(0, target, 8, 'w'); armed=true; armAddr=target.toString();
             send({t:'armed', addr:armAddr, tid:tid, note:'watch desc+8; expect builder store next cycle'}); }
        catch(e){ send({t:'arm_err', e:String(e)}); }
      }
    }
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ if(!done) send({t:'mon', nD:nD, nBP:nBP, armed:armed}); }, 3000);
