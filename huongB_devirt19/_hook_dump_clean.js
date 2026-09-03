// _hook_dump_clean.js — CLEAN dump of the slot16 producer, avoiding the Frida x16-clobber artifact.
//
// ROOT CAUSE FOUND (see STATUS 2026-08-27): the producer keeps state word 0 (IN0) LIVE in x16/w16 from
// the load at 0xa0e00 through the feed-forward whitening `eor w16,w4,w16` at 0xa0f70. Frida's inline hook
// trampoline reuses x16 (IP0) as branch-back scratch, so ANY hook in [a0e00, a0f70] overwrites the live
// w16 -> the captured `out` is computed with a garbage word0 (cascades through Loop A into ALL words).
// The previous _hook_dump.js hooked BOTH 0xa0e00 (IVLOAD) and 0xa0ed8 (RB_TOP) inside that zone, so its
// `out` was corrupted while `iv` (read in onEnter, before the load) stayed clean -> _compress.js saw
// clean-iv vs corrupted-out and failed 0/16 despite a byte-exact transcription (proven via _verifyA.js).
//
// FIX: hook only OUTSIDE the danger zone.
//   PRELOAD 0xa0de0  (NEON store block, just before the load; x9 already holds the output/state buffer)
//                    -> read iv = [x9+8, 32]. x16 clobber here is harmless: 0xa0e00 reloads w16 afterwards.
//   STORE   0xa0f90  (first stp after whitening) -> read 3 tables [sp,0x300] + x9. Whitening already used
//                    the real w16, so a post-whitening x16 clobber cannot affect the stored output.
//   ENTRY   0xa0748  (function prologue) onEnter stash arg0; onLeave read finished out = [arg0+8, 32].
// NO hook in [a0e00, a0f70]. memcpy@0x172a50 stays as a learner only.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const ENTRY=0xa0748, PRELOAD=0xa0de0, STORE=0xa0f90;
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82',
  '70208dae6764a6a7800499a4d2bef595','851dbc7109471d9b56f8c9c29ca143db','051afb6b2a4b02cdb42d28ab0f81b736'];
const wanted=new Set(KNOWN);
let base=null, lo=null, hi=null;
let nEntry=0, nStore=0, nRd=0, nEmit=0, done=false;
const MAX_EMIT=16;
const scratch=new Map();                 // tid -> {iv, tables, x9}

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent16(v){ if(!v)return 0; let z=0; for(let i=0;i<32;i+=2){ if(v.substr(i,2)==='00') z++; } return 16-z; }
function readHex(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function looksPtr(p){ try{ return p.compare(ptr('0x1000'))>=0 && p.compare(ptr('0x8000000000'))<0; }catch(e){ return false; } }
function windows(out){ if(!out||out.length<64) return []; return [
  {off:0,v:out.substr(0,32)},{off:8,v:out.substr(16,32)},{off:16,v:out.substr(32,32)}]; }
function knownWin(out){ for(const w of windows(out)){ if(wanted.has(w.v)) return w; } return null; }
function stopAll(reason){ done=true; send({t:'stopped', reason:reason, nEmit:nEmit, nEntry:nEntry, nStore:nStore, nRd:nRd}); }

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'clean hook-dump installed base='+base});

  // ---- memcpy learner: tag which outputs get read as slot16 (16B) from the pool ----
  try{ Interceptor.attach(base.add(MEMCPY), { onEnter(a){
    if(done) return;
    let sz; try{ sz=a[2].toInt32(); }catch(e){ return; } if(sz!==16) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra || ra.compare(lo)<0 || ra.compare(hi)>=0) return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let V; try{ V=hx(a[1].readByteArray(16)); }catch(e){ return; }
    if(ent16(V)<10 && !wanted.has(V)) return;
    if(!wanted.has(V)){ wanted.add(V); if(nRd<40) send({t:'rd', val:V, known:KNOWN.indexOf(V)>=0}); }
    nRd++;
  }}); }catch(e){ send({t:'err', where:'memcpy', e:String(e)}); }

  // ---- PRELOAD (0xa0de0): read the 32B initial state (IV) from [x9+8] BEFORE the load at 0xa0e00 ----
  try{ Interceptor.attach(base.add(PRELOAD), { onEnter(){
    if(done) return;
    const tid=this.threadId; let x9; try{ x9=this.context.x9; }catch(e){ return; }
    let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    sc.iv = x9? readHex(x9.add(8), 32) : null;
    sc.ivFull = x9? readHex(x9, 48) : null;
    sc.x9pre = x9? x9.toString() : null;
  }}); }catch(e){ send({t:'err', where:'preload', e:String(e)}); }

  // ---- STORE (0xa0f90): capture the 3 schedule tables + x9 (output base). AFTER whitening -> safe. ----
  try{ Interceptor.attach(base.add(STORE), { onEnter(){
    if(done) return; nStore++;
    const tid=this.threadId; let x9,sp; try{ x9=this.context.x9; sp=this.context.sp; }catch(e){ return; }
    let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    sc.x9=x9?x9.toString():null;
    sc.tables = sp? readHex(sp, 0x300) : null;
    sc.outAtStore = x9? readHex(x9.add(8), 32) : null;
  }}); }catch(e){ send({t:'err', where:'store', e:String(e)}); }

  // ---- ENTRY (0xa0748): stash arg0; on return read the finished OUTPUT and emit the full record ----
  try{ Interceptor.attach(base.add(ENTRY), {
    onEnter(a){
      if(done) return; nEntry++;
      this.out = a[0]; this.tid=this.threadId;
      const ctx=this.context; const args=[];
      for(let i=0;i<8;i++){ try{ const r=ctx['x'+i]; args.push({r:r.toString(), mem:looksPtr(r)?readHex(r,48):null}); }
        catch(e){ args.push({r:null,mem:null}); } }
      this.args=args;
    },
    onLeave(){
      if(done) return;
      const out = this.out? readHex(this.out.add(8), 32) : null;
      const sc = scratch.get(this.tid) || {}; scratch.delete(this.tid);
      const kw = knownWin(out) || knownWin(sc.outAtStore);
      if(nEmit>=MAX_EMIT){ stopAll('max_emit'); return; }
      nEmit++;
      send({ t:'DUMP', n:nEmit, known: kw? kw.v : null, knownOff: kw? kw.off : null,
             iv: sc.iv||null, ivFull: sc.ivFull||null, x9pre: sc.x9pre||null,
             out:out, outAtStore: sc.outAtStore||null, args:this.args,
             x9: sc.x9||null, tables: sc.tables||null });
      if(nEmit>=MAX_EMIT) stopAll('max_emit');
    }
  }); }catch(e){ send({t:'err', where:'entry', e:String(e)}); }

  setInterval(function(){ send({t:'mon', nEntry:nEntry, nStore:nStore, nRd:nRd, nEmit:nEmit, done:done}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
