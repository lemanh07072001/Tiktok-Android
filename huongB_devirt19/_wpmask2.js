// _wpmask2.js — DEFINITIVELY characterize ARM64 masked hardware write-watchpoints in this frida.
// Question: does setHardwareWatchpoint(id, addr, SIZE, 'w') accept SIZE>8 (power of 2) and give true
//   REGION semantics (a write anywhere in [addr, addr+SIZE) traps), not just an 8-byte BAS window?
// Method: on a stable low-volume libmetasec fn (0xa0748 compress) — which runs on a real app thread —
//   for each SIZE in [8,0x1000,0x10000,0x20000]: alloc a SIZE-aligned region, arm WP, write at the
//   MIDDLE (offset SIZE/2), see if it traps. A trap at the middle for SIZE>8 proves masked region works.
'use strict';
const SO='libmetasec_ov.so';
const COMPRESS=0xa0748;
const SIZES=[8, 0x1000, 0x10000, 0x20000];
let base=null, done=false;
let curExpect=null, sawTrap=false, lastPc=null;
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation') return false;                 // app null-checks: pass through
  if(d.type!=='breakpoint' && d.type!=='single-step') return false;
  sawTrap=true; try{ lastPc=d.context.pc.toString(); }catch(e){ lastPc=null; }
  try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){}
  return true;
});
function alignUp(p, sz){ const a=uint64(p.toString()); const m=uint64(sz-1); return ptr('0x'+a.add(m).and(m.not()).toString(16)); }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(COMPRESS), { onEnter(){
    if(done) return; done=true;
    const tid=Process.getCurrentThreadId();
    const th=Process.enumerateThreads().find(function(t){return t.id===tid;});
    send({t:'onthread', tid:tid, found:!!th});
    if(!th) return;
    const results=[];
    for(let k=0;k<SIZES.length;k++){
      const sz=SIZES[k];
      const raw=Memory.alloc(sz*2);
      const region=alignUp(raw, sz);
      const target=(sz===8)?region:region.add(sz/2);          // write at MIDDLE for sz>8
      let armed=false, armErr=null;
      sawTrap=false; lastPc=null;
      try{ th.setHardwareWatchpoint(0, region, sz, 'w'); armed=true; }
      catch(e){ armErr=String(e); }
      if(armed){
        try{ target.writeU32(0x41424344); }catch(e){}
        try{ th.unsetHardwareWatchpoint(0); }catch(e){}
      }
      results.push({size:sz, region:region.toString(), target:target.toString(),
                    armed:armed, armErr:armErr, trapped:sawTrap, pc:lastPc});
      send({t:'sz', r:results[results.length-1]});
    }
    send({t:'RESULT', results:results});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ if(!done) send({t:'timeout_no_compress'}); }, 30000);
