// _wptest.js — CHARACTERIZE a hardware write-watchpoint hit SAFELY.
// Rule learned: the app fires access-violation SIGSEGVs constantly (ART implicit null-checks). We MUST
// return false for those so the app's own handler processes them. Only NON-access-violation exceptions
// are candidates for our watchpoint trap. We arm a WP on our own buffer, write to it, and log the type.
'use strict';
let curThread=null, myBuf=null, sawWP=false, nAV=0;
Process.setExceptionHandler(function(d){
  // pass through the app's null-check faults untouched
  if(d.type === 'access-violation'){ nAV++; return false; }
  // anything else: log it fully (this is what a watchpoint/breakpoint looks like)
  let mem=null, op=null;
  try{ if(d.memory){ mem=d.memory.address?d.memory.address.toString():null; op=d.memory.operation; } }catch(e){}
  const pc=(d.context&&d.context.pc)?d.context.pc.toString():null;
  send({t:'EXC', type:d.type, pc:pc, mem:mem, op:op, tid:Process.getCurrentThreadId(),
        isMyBuf: (mem && myBuf && mem===myBuf.toString())});
  sawWP=true;
  try{ if(curThread) curThread.unsetHardwareWatchpoint(0); }catch(e){}
  return true;   // we recognized/handled our own trap
});
myBuf = Memory.alloc(64);
const tid = Process.getCurrentThreadId();
curThread = Process.enumerateThreads().find(function(t){return t.id===tid;});
send({t:'setup', tid:tid, foundThread:!!curThread, buf:myBuf.toString()});
try{ curThread.setHardwareWatchpoint(0, myBuf, 8, 'w'); send({t:'armed', addr:myBuf.toString()}); }
catch(e){ send({t:'arm_err', e:String(e)}); }
try{ myBuf.writeU64(uint64('0x4141414141414141')); send({t:'wrote', sawWP:sawWP}); }
catch(e){ send({t:'write_err', e:String(e)}); }
setTimeout(function(){ send({t:'final', sawWP:sawWP, nAV:nAV}); }, 800);
