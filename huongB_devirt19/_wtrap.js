// _wtrap.js — Catch the PRODUCER store PC by page-fault trapping writes into the custom slab arena.
// Established: P is born in a large anonymous rw- slab (e.g. 0x77e4bd4000, ~3MB, file=null), NOT via any
// hookable libc allocator. HW WP only covers 8 bytes here, too small for a 3MB region. So: mprotect the slab
// READ-ONLY; the producer's 16-byte store faults -> SIGSEGV handler logs the faulting PC (=producer instr) +
// target addr, restores RW, lets it retry. To avoid a fault-flood (watchdog ANR), we toggle: an interval arms
// (RO) at most every INTERVAL ms; the handler disarms (RW) on the first fault. => <=~20 faults/sec.
// Noise filtering is OFFLINE by FREQUENCY: the producer is ONE instruction hit every cycle, so its PC recurs;
// random first-writers scatter. The dominant libmetasec PC that stores into a fresh slab slot = producer.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const INTERVAL=50;                       // ms between re-arms (bounds fault rate)
let base=null, lo=null, hi=null;
let region=null;                         // {base:NativePointer, size:Number}
let protectedNow=false, arms=0, faults=0, done=false; const MAXF=250;
const pcTally={};                        // selfOff -> count
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function inRegion(p){ try{ return region && p.compare(region.base)>=0 && p.compare(region.base.add(region.size))<0; }catch(e){ return false; } }
function disarm(){ if(region && protectedNow){ try{ Memory.protect(region.base, region.size, 'rw-'); }catch(e){} protectedNow=false; } }
function arm(){ if(done||!region||protectedNow) return; try{ if(Memory.protect(region.base, region.size, 'r--')){ protectedNow=true; arms++; } }catch(e){} }
Process.setExceptionHandler(function(d){
  if(d.type!=='access-violation') return false;
  let addr=null; try{ addr=d.memory?d.memory.address:null; }catch(e){}
  if(!addr || !inRegion(addr)) return false;         // not our trap -> pass through
  // our trap: record producer-candidate PC, restore RW, retry
  let pc=null; try{ pc=d.context.pc; }catch(e){}
  disarm();
  faults++;
  const inLib=pc?inSelf(pc):false;
  const key=pc?selfOff(pc):'?';
  pcTally[key]=(pcTally[key]||0)+1;
  // capture a little context on the first several, and on any in-lib PC
  if(faults<=MAXF && (inLib || faults<=40)){
    const c=d.context; const regs={};
    ['x0','x1','x2','x3','x8','x9','x10','x19','x20','x21'].forEach(function(r){ try{ regs[r]=c[r].toString(); }catch(e){} });
    send({t:'FAULT', f:faults, pc:key, pcMod:pc?modOff(pc):null, inLib:inLib, addr:addr.toString(),
          slotOff:region?addr.sub(region.base).toInt32():null, tid:d.thread?d.thread.id:null, regs:inLib?regs:undefined});
  }
  if(faults>=MAXF){ done=true; disarm(); }
  return true;                                        // retry the faulting instruction (now RW)
});
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(region) return; const c=this.context; const x0=c.x0; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return; let v0=null; try{ v0=x0.readByteArray(16); }catch(e){}
    if(!v0) return;
    let r=null; try{ r=Process.findRangeByAddress(x0); }catch(e){}
    if(r){ region={base:r.base, size:r.size}; send({t:'region', base:r.base.toString(), size:'0x'+r.size.toString(16), prot:r.protection, firstP:x0.toString()}); }
    else send({t:'no_region', P:x0.toString()});
  }});
  send({t:'ready'});
  setInterval(arm, INTERVAL);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){
  // report top PCs by frequency
  const top=Object.keys(pcTally).map(function(k){return [k,pcTally[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,8);
  send({t:'mon', arms:arms, faults:faults, region:!!region, top:top});
}, 3000);
