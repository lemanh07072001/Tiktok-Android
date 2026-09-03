// _hook_dump.js — DUMP the slot16 producer via plain Interceptor hooks (fires on ALL threads).
// Rationale (see note 53 + this session): Stalker-follow only tracked the memcpy-reader thread, which
// mostly READS cached slot16 from the pool; the producer (0xa0748) actually runs on OTHER (signing/worker)
// threads. Now that the PCs are pinned, Interceptor.attach on each PC fires on every thread automatically,
// with no JIT / no nterp-callback crash and low overhead.
//
// Producer layout (offsets in libmetasec_ov.so, sha1 a9c74e4f...):
//   ENTRY  0xa0748  first prologue insn `stp x28,x27,[sp,#-0x60]!`; x0=arg0=OUTPUT buf, x1..x7=other args.
//   RB_TOP 0xa0ed8  Loop B (compress) top, 64 iters; x0=round index. Gate x0==0 -> INITIAL state x0..x28.
//   STORE  0xa0f90  after whitening; x9=output buf, sp=frame base -> 3 schedule tables [sp, 0x300],
//                   output 32B at [x9+8, 32]. slot16 = a 16B window of that block.
//
// We hook ENTRY with onEnter/onLeave (it IS the function entry, so onLeave is valid). Mid hooks (RB_TOP,
// STORE) stash their captures in a per-tid scratch object (the call is synchronous & non-reentrant on a
// thread), consumed by ENTRY.onLeave which reads the finished OUTPUT from arg0's buffer and emits one full
// record. memcpy@0xa0440 stays only as a *learner* to grow `wanted` (tag which outputs get read as slot16).
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const ENTRY=0xa0748, IVLOAD=0xa0e00, RB_TOP=0xa0ed8, STORE=0xa0f90;
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82',
  '70208dae6764a6a7800499a4d2bef595','851dbc7109471d9b56f8c9c29ca143db','051afb6b2a4b02cdb42d28ab0f81b736'];
const wanted=new Set(KNOWN);
let base=null, lo=null, hi=null;
let nEntry=0, nStore=0, nRd=0, nEmit=0, done=false;
const MAX_EMIT=16;
const scratch=new Map();              // tid -> {round0, tables, spStore, x9}

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent16(v){ if(!v)return 0; let z=0; for(let i=0;i<32;i+=2){ if(v.substr(i,2)==='00') z++; } return 16-z; }
function readHex(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function looksPtr(p){ try{ const v=p; return v.compare(ptr('0x1000'))>=0 && v.compare(ptr('0x8000000000'))<0; }catch(e){ return false; } }
function windows(out){ if(!out||out.length<64) return []; return [
  {off:0,v:out.substr(0,32)},{off:8,v:out.substr(16,32)},{off:16,v:out.substr(32,32)}]; }
function knownWin(out){ for(const w of windows(out)){ if(wanted.has(w.v)) return w; } return null; }

function stopAll(reason){
  done=true;
  send({t:'stopped', reason:reason, nEmit:nEmit, nEntry:nEntry, nStore:nStore, nRd:nRd});
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'hook-dump installed base='+base});

  // ---- memcpy learner: grow `wanted` with slot16 values actually read from the pool ----
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

  // ---- IVLOAD (0xa0e00): capture the 32B initial state (IV) loaded from [x9+8] before the loops ----
  try{ Interceptor.attach(base.add(IVLOAD), { onEnter(){
    if(done) return;
    const ctx=this.context; const tid=this.threadId;
    let x9; try{ x9=ctx.x9; }catch(e){ return; }
    let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    sc.iv = x9? readHex(x9.add(8), 32) : null;            // IN[0..7] fed into Loop A
    sc.ivFull = x9? readHex(x9, 48) : null;               // include x9+0 window for context
  }}); }catch(e){ send({t:'err', where:'ivload', e:String(e)}); }

  // ---- RB_TOP: capture the round-0 initial compression state ----
  try{ Interceptor.attach(base.add(RB_TOP), { onEnter(){
    if(done) return;
    const ctx=this.context;
    let r0; try{ r0=ctx.x0; }catch(e){ return; }
    if(!r0 || r0.toInt32()!==0) return;                 // only round 0
    const tid=this.threadId; let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    if(sc.round0) return;
    const o={}; for(let i=0;i<=28;i++){ try{ o['x'+i]=ctx['x'+i].toString(); }catch(e){ o['x'+i]=null; } }
    try{ o.sp=ctx.sp.toString(); }catch(e){}
    sc.round0=o;
  }}); }catch(e){ send({t:'err', where:'rbtop', e:String(e)}); }

  // ---- STORE: capture 3 schedule tables + output 32B ----
  try{ Interceptor.attach(base.add(STORE), { onEnter(){
    if(done) return;
    nStore++;
    const ctx=this.context; const tid=this.threadId;
    let x9,sp; try{ x9=ctx.x9; sp=ctx.sp; }catch(e){ return; }
    let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    sc.x9=x9?x9.toString():null;
    sc.spStore=sp?sp.toString():null;
    sc.tables = sp? readHex(sp, 0x300) : null;           // sp, sp+0x100, sp+0x200 (3x256B)
    sc.outAtStore = x9? readHex(x9.add(8), 32) : null;    // snapshot right at store time
  }}); }catch(e){ send({t:'err', where:'store', e:String(e)}); }

  // ---- ENTRY: args in, and on return read the finished OUTPUT; emit full record ----
  try{ Interceptor.attach(base.add(ENTRY), {
    onEnter(a){
      if(done) return;
      nEntry++;
      this.out = a[0];                                   // arg0 = output buffer
      const ctx=this.context; const args=[];
      for(let i=0;i<8;i++){ try{
        const r=ctx['x'+i]; const mem = looksPtr(r)? readHex(r, 48) : null;
        args.push({r:r.toString(), mem:mem});
      }catch(e){ args.push({r:null,mem:null}); } }
      this.args=args;
      this.tid=this.threadId;
    },
    onLeave(){
      if(done) return;
      const out = this.out? readHex(this.out.add(8), 32) : null;   // finished 32B output
      const sc = scratch.get(this.tid) || {};
      scratch.delete(this.tid);
      const kw = knownWin(out) || knownWin(sc.outAtStore);
      // emit every producer call (capped); tag whether output window is a known/read slot16
      if(nEmit>=MAX_EMIT){ stopAll('max_emit'); return; }
      nEmit++;
      send({ t:'DUMP', n:nEmit, known: kw? kw.v : null, knownOff: kw? kw.off : null,
             iv: sc.iv||null, ivFull: sc.ivFull||null,
             out:out, outAtStore: sc.outAtStore||null,
             args:this.args, round0: sc.round0||null,
             x9: sc.x9||null, spStore: sc.spStore||null, tables: sc.tables||null });
      if(nEmit>=MAX_EMIT) stopAll('max_emit');
    }
  }); }catch(e){ send({t:'err', where:'entry', e:String(e)}); }

  setInterval(function(){ send({t:'mon', nEntry:nEntry, nStore:nStore, nRd:nRd, nEmit:nEmit, done:done}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
