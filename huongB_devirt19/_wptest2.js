// _wptest2.js — characterize a HW write-watchpoint hit on a REAL app thread.
// Hook SM3 compress 0xa0748 (runs on the signing thread, bounded volume). On the first entry, arm a
// write-WP on a scratch buffer and immediately write to it -> the trap fires synchronously on THIS app
// thread. Log what Process.setExceptionHandler receives so we know how to recognize watchpoint traps.
'use strict';
const SO='libmetasec_ov.so';
const COMPRESS=0xa0748;
let base=null, lo=null, hi=null, tested=false, sawWP=false, nAV=0;
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation'){ nAV++; return false; }   // pass app null-checks through
  let mem=null, op=null;
  try{ if(d.memory){ mem=d.memory.address?d.memory.address.toString():null; op=d.memory.operation; } }catch(e){}
  const pc=(d.context&&d.context.pc)?d.context.pc.toString():null;
  send({t:'EXC', type:d.type, pc:pc, mem:mem, op:op, tid:Process.getCurrentThreadId()});
  sawWP=true;
  try{ Process.enumerateThreads().forEach(function(t){ try{t.unsetHardwareWatchpoint(0);}catch(e){} }); }catch(e){}
  return true;
});
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(COMPRESS), { onEnter(){
    if(tested) return; tested=true;
    const tid=Process.getCurrentThreadId();
    const th=Process.enumerateThreads().find(function(t){return t.id===tid;});
    const buf=Memory.alloc(64);
    send({t:'selftest', tid:tid, foundThread:!!th, buf:buf.toString()});
    if(!th) return;
    try{ th.setHardwareWatchpoint(0, buf, 8, 'w'); send({t:'armed', addr:buf.toString()}); }
    catch(e){ send({t:'arm_err', e:String(e)}); return; }
    try{ buf.writeU64(uint64('0x4242424242424242')); send({t:'wrote_after', sawWP:sawWP}); }
    catch(e){ send({t:'write_err', e:String(e)}); }
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ send({t:'final', sawWP:sawWP, nAV:nAV}); }, 5000);
