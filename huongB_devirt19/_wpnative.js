// _wpnative.js — Two questions in one controlled run:
//  Q1 (delivery): when the APP's OWN native code (the SM3 copy at 0x172a50) stores into a watched 8-byte
//     location, is the trap delivered to Process.setExceptionHandler (giving us pc) — or lost/js-wrapped?
//  Q2 (stability): is the memcpy DESTINATION (args[0]=SM3 block) a STABLE address across requests? A stable
//     buffer that the producer/consumer writes every request would sidestep the marching-arena problem.
// Method: hook 0x172a50 (ret==0xa0440, sz==16). Log dst,src,val. After a few readers, arm an 8-byte WRITE
//   WP on the chosen dst on the signing thread INSIDE onEnter, then let the intercepted memcpy run: its
//   native store into dst should trap. If setExceptionHandler fires with an inSelf pc -> native delivery works.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, done=false;
let nRd=0, armed=false, armAddr=null, nBP=0;
const dsts=[]; const hits=[];
function selfOff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation') return false;
  if(d.type!=='breakpoint' && d.type!=='single-step') return false;
  nBP++;
  let pc=null,mem=null,op=null;
  try{ pc=d.context.pc; }catch(e){}
  try{ if(d.memory){ mem=d.memory.address?d.memory.address.toString():null; op=d.memory.operation; } }catch(e){}
  const rec={n:nBP, pc:pc?selfOff(pc):null, pcRaw:pc?pc.toString():null, inSelf:pc?inSelf(pc):false, mem:mem, op:op, tid:Process.getCurrentThreadId()};
  hits.push(rec); send({t:'BP', rec:rec});
  try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){}
  armed=false;
  return true;
});
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done) return;
    let dst,src,sz; try{ dst=args[0]; src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nRd++;
    const ds=dst.toString(), ss=src.toString();
    if(!dsts.some(function(x){return x===ds;})) dsts.push(ds);
    send({t:'rd', ord:nRd, tid:this.threadId, dst:ds, src:ss, val:val, distinctDst:dsts.length});
    // After 4 readers, arm an 8-byte WP on THIS dst; the intercepted memcpy about to run will store into it.
    if(nRd>=4 && !armed){
      const tid=this.threadId;
      const th=Process.enumerateThreads().find(function(t){return t.id===tid;});
      if(th){
        try{ th.setHardwareWatchpoint(0, dst, 8, 'w'); armed=true; armAddr=ds;
             send({t:'armed', addr:ds, tid:tid, note:'expect native memcpy store to trap NOW'}); }
        catch(e){ send({t:'arm_err', e:String(e)}); }
      }
    }
    if(nBP>=4){ done=true; send({t:'stopped', hits:hits, distinctDst:dsts.length, dsts:dsts.slice(0,8)}); }
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ if(!done) send({t:'mon', nRd:nRd, nBP:nBP, armed:armed, distinctDst:dsts.length}); }, 4000);
