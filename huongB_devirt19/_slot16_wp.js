// _slot16_wp.js — catch the slot16 PRODUCER store via ARM64 hardware write-watchpoints.
// Strategy: the reliable reader (0x172a50, ret==0xa0440, sz==16) gives us P = the pool addr holding a
//   freshly-produced slot16, on the signing thread. The pool is a small reused slab band (0x77e508..0x77e509).
//   We arm hardware WRITE-watchpoints on the last few P's (ARM64 has 4 WP slots) on the signing thread.
//   On a FUTURE signing, when the producer (inside the 0x55950 VM) writes a new slot16 into a reused slot,
//   the watchpoint traps -> Process.setExceptionHandler gives us context.pc = the PRODUCER STORE PC.
// SAFE: HW watchpoints are CPU-side (no Stalker, no wedging); exception handler is O(1). We unset-on-hit to
//   avoid re-trap loops and re-arm on the next reader.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, nRd=0, nHit=0, done=false;
let sigTid=null, thObj=null;
const WPN=4;                          // ARM64 watchpoint slots
const recentP=[];                     // ring of last WPN pool addrs
const hits=[];                        // {pc, pcoff, memAddr, op, tid}
function selfOff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}

function threadFor(tid){
  try{ return Process.enumerateThreads().find(function(t){return t.id===tid;}) || null; }catch(e){ return null; }
}
function armWatchpoints(){
  const t = threadFor(sigTid); if(!t){ send({t:'arm_miss', tid:sigTid}); return; }
  thObj = t;
  let armed=[];
  for(let i=0;i<recentP.length && i<WPN;i++){
    try{ t.setHardwareWatchpoint(i, recentP[i], 8, 'w'); armed.push(recentP[i].toString()); }
    catch(e){ send({t:'arm_err', slot:i, e:String(e)}); }
  }
  send({t:'armed', tid:sigTid, slots:armed});
}
function unarmAll(){
  if(!thObj) return;
  for(let i=0;i<WPN;i++){ try{ thObj.unsetHardwareWatchpoint(i); }catch(e){} }
}

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});

  Process.setExceptionHandler(function(details){
    // Only interested in watchpoint/breakpoint traps
    try{
      const ctx=details.context; const pc=ctx.pc;
      const memA = details.memory ? details.memory.address : null;
      const op   = details.memory ? details.memory.operation : null;
      // Only treat libmetasec-originated writes as producer candidates; ignore others but log type once.
      nHit++;
      const rec={n:nHit, type:details.type, pc:selfOff(pc), pcRaw:pc.toString(),
                 inSelf:inSelf(pc), mem:memA?memA.toString():null, op:op, tid:Process.getCurrentThreadId()};
      hits.push(rec);
      send({t:'HIT', rec:rec});
      // stop the trap: unset all WPs on this thread (avoid re-fire loop), flag re-arm on next reader
      unarmAll();
      if(nHit>=12){ done=true; send({t:'stopped_hits', hits:hits}); }
      return true;   // handled -> resume
    }catch(e){ send({t:'exc_err', e:String(e)}); return false; }
  });

  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done)return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nRd++;
    sigTid=this.threadId;
    // push P into ring (front = most recent), keep distinct, cap WPN
    const ps=src.toString();
    if(!recentP.some(function(p){return p.toString()===ps;})){
      recentP.unshift(src); if(recentP.length>WPN) recentP.length=WPN;
    }
    send({t:'rd', ord:nRd, tid:sigTid, P:ps, slot16:val, ringP:recentP.map(function(p){return p.toString();})});
    armWatchpoints();     // (re)arm on the signing thread with the freshest P set
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
