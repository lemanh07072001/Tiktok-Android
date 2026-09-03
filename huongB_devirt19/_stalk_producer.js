// _stalk_producer.js — reader-anchored single-pass Stalker to localize the slot16 PRODUCER PC.
// MAM is exhausted (re-protect crashes; pool arena is a hot shared binder/graphics heap). Pivot to Stalker.
// STRATEGY:
//  - Anchor: Interceptor on memcpy 0x172a50. At the a0440 read-bucket (size==16, high-entropy src) we KNOW a
//    signing burst is live on THIS thread and we learn the slot16 value(s). The producer for value #1 already
//    ran, but the register burst emits ~12 distinct slot16 -> once we Stalker.follow this thread, the
//    producers for values #2..#12 get instrumented.
//  - transform: instrument ONLY 16-byte single-shot stores (str q / stur q / stp / stnp / st1) whose PC is in
//    libmetasec. Stalker caches translated blocks, so the ~97k VM dispatch loop compiles once; callouts fire
//    only on those stores.
//  - callout runs AFTER the store (we keep() then putCallout) and reads the 16 DESTINATION bytes (no need to
//    read Q regs, which arm64 CpuContext doesn't expose). If they match a wanted slot16 -> insn.address = the
//    producer PC. Unfollow immediately.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82'];
let base=null, lo=null, hi=null;
let nRd=0, nStores=0, nCallouts=0, nHits=0, done=false;
const followed=new Set();                 // tids currently followed (every signing thread, not just the first)
const producedAt=new Map();               // slot16 hex -> {off,mnem}: EVERY dense pool store's PC (causal record)
const MAP_MAX=20000;
const wanted=new Set(KNOWN);              // slot16 values to match (seeded + learned live at the reader)
const MAX_CALLOUTS=8000000;              // runaway backstop -> unfollow
const INCLUDE_STP=true;                   // producer likely stores the 16B ARX result via stp (GPR pair), not str q.
const POOL_LO=ptr('0x77e4000000'), POOL_HI=ptr('0x77e6000000');   // slot16 pool band (reader src region)
const PTR_LO=ptr('0x1000'), PTR_HI=ptr('0x8000000000');           // sane userspace ptr guard (stack+heap+arenas)
function readReg(context, name){
  if(name==='x29') name='fp'; else if(name==='x30') name='lr';
  else if(name==='wsp') name='sp';
  try{ return context[name]; }catch(e){ return null; }
}
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function inLib(p){ return p.compare(lo)>=0 && p.compare(hi)<0; }

// classify a store insn: is it a 16-byte one-shot? return the destination {base, disp} or null.
function memDest(insn){
  let mem=null;
  for(const op of insn.operands){ if(op.type==='mem'){ mem=op.value; break; } }
  if(!mem || !mem.base) return null;
  return { base: mem.base, disp: (mem.disp||0) };
}
function isWideStore(insn){
  const m=insn.mnemonic;
  if(INCLUDE_STP && (m==='stp'||m==='stnp')) return true;   // store pair = 16 bytes; opt-in (noisy: reg spills)
  if(m==='str'||m==='stur'||m==='st1'){
    for(const op of insn.operands){ if(op.type==='reg' && /^[qv]/.test(op.value)) return true; } // 128-bit SIMD
  }
  return false;
}

function stopAll(reason){
  for(const tid of followed){ try{ Stalker.unfollow(tid); }catch(e){} }
  try{ Stalker.flush(); }catch(e){}
  followed.clear();
  send({t:'unfollow', reason:reason, nStores:nStores, nCallouts:nCallouts, nHits:nHits});
}

function looksLikeSlot16(v){                 // dense 16-byte value; reject struct/counter headers (mostly zero)
  if(!v) return false;
  let z=0; for(let i=0;i<32;i+=2){ if(v.substr(i,2)==='00') z++; }
  return z<7;
}
function makeCallout(destBase, destDisp, pcStr, pcOff){
  const offStr='0x'+pcOff.toString(16);
  return function(context){
    if(done) return;
    nCallouts++;
    let addr = readReg(context, destBase);
    if(!addr) return;
    if(destDisp) addr = addr.add(destDisp);
    // NO pool-band filter: the ARX materializes slot16 in a SCRATCH buffer (stack/other arena); only the final
    // copy lands in the pool. So instrument dense 16B stores ANYWHERE. Guard against wild pointers before reading.
    if(addr.compare(PTR_LO)<0 || addr.compare(PTR_HI)>=0){
      if(nCallouts>=MAX_CALLOUTS) stopAll('max_callouts');
      return;
    }
    let val=null; try{ val=hx(addr.readByteArray(16)); }catch(e){ return; }
    if(!looksLikeSlot16(val)){ if(nCallouts>=MAX_CALLOUTS) stopAll('max_callouts'); return; }
    // KNOWN value produced live under our watch -> definitive producer, stop now.
    if(wanted.has(val)){
      done=true; send({t:'PRODUCER_PC', off:offStr, mnem:pcStr, val:val, addr:addr.toString(), via:'store-known'});
      stopAll('producer_known'); return;
    }
    // record value->PC. The reader will later confirm which of these is a real slot16 (causal store-then-read).
    if(!producedAt.has(val)){
      if(producedAt.size<MAP_MAX) producedAt.set(val, {off:offStr, mnem:pcStr});
      if(nHits<24){ nHits++; send({t:'STORE_HIT', off:offStr, addr:addr.toString(), val:val, mnem:pcStr, mapsz:producedAt.size}); }
    }
    if(nCallouts>=MAX_CALLOUTS) stopAll('max_callouts');
  };
}

let excluded=false;
function excludeOthers(){
  if(excluded) return; excluded=true;
  // libmetasec calls back into Java mid-signing (CallStaticObjectMethodV -> ms.bd.o.k.b). If Stalker follows the
  // thread into libart's nterp interpreter it null-derefs. Exclude EVERY module except libmetasec so those calls
  // run native (Stalker trampolines out and resumes on return). Keeps instrumentation to libmetasec only.
  let n=0;
  for(const m of Process.enumerateModules()){
    if(m.name===SO) continue;
    try{ Stalker.exclude({base:m.base, size:m.size}); n++; }catch(e){}
  }
  send({t:'excluded', n:n});
}
function startFollow(){
  const tid = Process.getCurrentThreadId();
  if(followed.has(tid)) return;
  excludeOthers();
  followed.add(tid);
  send({t:'follow_start', tid:tid, nFollowed:followed.size});
  Stalker.follow(tid, {
    transform: function(iterator){
      let insn;
      while((insn = iterator.next()) !== null){
        const pc=insn.address, isLib=inLib(pc);
        if(isLib && isWideStore(insn)){
          const d=memDest(insn);
          iterator.keep();                              // emit the store FIRST
          // skip stack spills: producer stores into a POOL buffer via a GP reg (x19-like), never sp/fp.
          if(d && !/^(sp|wsp|fp|x29)$/.test(d.base)){
            nStores++;
            iterator.putCallout(makeCallout(d.base, d.disp, insn.mnemonic, pc.sub(base)));
          }
          continue;
        }
        iterator.keep();
      }
    }
  });
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'stalk-producer installed base='+base});
  Interceptor.attach(base.add(MEMCPY), { onEnter(args){
    if(done) return;
    let sz; try{ sz=args[2].toInt32(); }catch(e){ return; } if(sz!==16) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra || ra.compare(lo)<0 || ra.compare(hi)>=0) return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let src,V; try{ src=args[1]; V=hx(src.readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10 && !wanted.has(V)) return;
    nRd++;
    wanted.add(V);                                       // learn THIS run's slot16 values
    // CAUSAL MATCH: was this exact value stored into the pool under our watch? that store PC is the producer.
    const p=producedAt.get(V);
    if(p && !done){ done=true; send({t:'PRODUCER_PC', off:p.off, mnem:p.mnem, val:V, via:'store-then-read'}); stopAll('producer_via_map'); }
    if(nRd<=40) send({t:'rd', ord:nRd, src:src.toString(), val:V, known:KNOWN.indexOf(V)>=0, tid:Process.getCurrentThreadId(), inmap:!!p});
    startFollow();                                       // follow EVERY signing thread we discover (no-op if already followed)
  }});
  setInterval(function(){ send({t:'mon', nRd:nRd, nFollowed:followed.size, nStores:nStores, nCallouts:nCallouts, mapsz:producedAt.size, done:done}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
