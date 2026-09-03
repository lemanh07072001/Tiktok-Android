// _wpfire.js — Does a HW write-watchpoint ACTUALLY fire on this emulator, and via what write path?
// Two write mechanisms compared, both executed on the SAME app thread we armed (inside onEnter):
//   (A) frida Memory.writeU64  — may bypass a real CPU store (frida-internal memory poke)
//   (B) libc memset via NativeFunction — a REAL store instruction stream on this thread
// If (B) traps but (A) doesn't -> WPs work but only catch real target-code stores (perfect for our goal).
// If NEITHER traps for size=8 -> HW debug regs are not virtualized on this emulator -> abandon WP approach.
// Also test size=0x20000 with a MIDDLE memset to confirm masked REGION semantics.
'use strict';
const SO='libmetasec_ov.so';
const COMPRESS=0xa0748;
let base=null, done=false, sawTrap=false, lastPc=null, lastMem=null;
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation') return false;
  if(d.type!=='breakpoint' && d.type!=='single-step') return false;
  sawTrap=true;
  try{ lastPc=d.context.pc.toString(); }catch(e){}
  try{ lastMem=(d.memory&&d.memory.address)?d.memory.address.toString():null; }catch(e){}
  try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){}
  return true;
});
function alignUp(p, sz){ const a=uint64(p.toString()); const m=uint64(sz-1); return ptr('0x'+a.add(m).and(m.not()).toString(16)); }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; send({t:'info', base:base.toString()});
  const memsetP=Module.findGlobalExportByName('memset');
  const memset=new NativeFunction(memsetP, 'pointer', ['pointer','int','ulong']);
  Interceptor.attach(base.add(COMPRESS), { onEnter(){
    if(done) return; done=true;
    const tid=Process.getCurrentThreadId();
    const th=Process.enumerateThreads().find(function(t){return t.id===tid;});
    send({t:'onthread', tid:tid, found:!!th, memset:memsetP.toString()});
    if(!th) return;
    function trial(label, sz, useMemset, midOffset){
      const raw=Memory.alloc(sz*2); const region=alignUp(raw, sz);
      const target=region.add(midOffset||0);
      let armed=false, armErr=null; sawTrap=false; lastPc=null; lastMem=null;
      try{ th.setHardwareWatchpoint(0, region, sz, 'w'); armed=true; }catch(e){ armErr=String(e); }
      if(armed){
        try{ if(useMemset) memset(target, 0x41, 8); else target.writeU64(uint64('0x4242424242424242')); }catch(e){ send({t:'werr', e:String(e)}); }
        try{ th.unsetHardwareWatchpoint(0); }catch(e){}
      }
      const r={label:label, size:sz, region:region.toString(), target:target.toString(), via:useMemset?'memset':'frida', armed:armed, armErr:armErr, trapped:sawTrap, pc:lastPc, mem:lastMem};
      send({t:'trial', r:r}); return r;
    }
    trial('sz8-frida', 8, false, 0);
    trial('sz8-memset', 8, true, 0);
    trial('sz0x20000-memset-mid', 0x20000, true, 0x10000);
    send({t:'DONE'});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ if(!done) send({t:'timeout_no_compress'}); }, 30000);
