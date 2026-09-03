// _stalk_dump.js — HYBRID DUMP of the slot16 producer's runtime inputs/state/output.
// Producer localized (note 53): entry 0xa0748; schedule Loop A @0xa0e40 (16 iters -> 3 tables of 0x100 at
// sp/sp+0x100/sp+0x200); compress Loop B @0xa0ed8 (64 iters, ARX+CH); store 32B @0xa0f90 to [x9,#0x8..0x28]
// where x9=arg0=output buffer. slot16 = a 16-byte window of that 32-byte block; later memcpy'd to pool and
// read at 0xa0440. We reuse the WORKING Stalker rig (exclude-others so JNI->nterp callbacks don't crash).
//
// Callouts at 3 in-function PCs (each runs ~once/call, low volume):
//   ENTRY  0xa0748  -> push a per-thread frame recording x0..x7 (candidate PSK ptr / seed / output ptr).
//   RB_TOP 0xa0ed8  -> at round 0 (x0==0) snapshot x0..x28 = the INITIAL compression state feeding Loop B.
//   STORE  0xa0f90  -> read output [x9+8,32] and the 3 schedule tables [sp,0x300]; if any 16B window of the
//                      output is a KNOWN/learned slot16, EMIT the full record {args, round0 regs, tables,
//                      output}. This pins (schedule tables -> slot16) and (initial state -> slot16) as
//                      ground-truth for an offline node reimplementation of the clean core.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const ENTRY=0xa0748, RB_TOP=0xa0ed8, STORE=0xa0f90;
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82',
  '70208dae6764a6a7800499a4d2bef595','851dbc7109471d9b56f8c9c29ca143db','051afb6b2a4b02cdb42d28ab0f81b736'];
const wanted=new Set(KNOWN);
let base=null, lo=null, hi=null;
const followed=new Set();
const callStack=new Map();            // tid -> array<frame>  (per-thread, handles nested calls)
let nRd=0, nEntry=0, nStore=0, nEmit=0, done=false;
const MAX_EMIT=10;

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v)return 0; let z=0; for(let i=0;i<v.length;i+=2){ if(v.substr(i,2)==='00') z++; } return 16-z; }
function inLib(p){ return p.compare(lo)>=0 && p.compare(hi)<0; }
function rd(ctx,name){ try{ return ctx[name]; }catch(e){ return null; } }
function readHex(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function looksLikeSlot16(v){ if(!v||v.length<32) return false; let z=0; for(let i=0;i<32;i+=2){ if(v.substr(i,2)==='00') z++; } return z<7; }
function frameFor(tid){ let s=callStack.get(tid); if(!s){ s=[]; callStack.set(tid,s); } return s; }

function dumpX(ctx,loI,hiI){ const o={}; for(let i=loI;i<=hiI;i++){ const r=rd(ctx,'x'+i); o['x'+i]= r?r.toString():null; } return o; }

// windows of the 32-byte output that could be slot16 (16B slice at byte offsets 0/8/16)
function windows(out){ if(!out||out.length<32) return []; return [
  {off:0, v:out.substr(0,32)}, {off:8, v:out.substr(16,32)}, {off:16, v:out.substr(32,32)} ]; }

function onEntry(ctx){
  if(done) return;
  nEntry++;
  const s=frameFor(Process.getCurrentThreadId());
  if(s.length>8) s.shift();                                  // cap leaked frames (early-return paths)
  s.push({ x:dumpX(ctx,0,7), round0:null });
}
function onRoundTop(ctx){
  if(done) return;
  const x0=rd(ctx,'x0'); if(!x0 || x0.toInt32()!==0) return; // only the FIRST compression round
  const s=callStack.get(Process.getCurrentThreadId()); if(!s||!s.length) return;
  const f=s[s.length-1]; if(f.round0) return;
  f.round0=dumpX(ctx,0,28);
  f.round0.sp=(rd(ctx,'sp')||{toString:()=>null}).toString();
}
function onStore(ctx){
  if(done) return;
  nStore++;
  const tid=Process.getCurrentThreadId();
  const s=callStack.get(tid);
  const f=(s&&s.length)? s.pop() : null;
  const x9=rd(ctx,'x9'), sp=rd(ctx,'sp'); if(!x9) return;
  const out=readHex(x9.add(8), 32);
  if(!looksLikeSlot16(out)) return;
  // does any 16B window equal a known/learned slot16?
  let hit=null; for(const w of windows(out)){ if(wanted.has(w.v)){ hit=w; break; } }
  if(!hit) return;                                           // only emit slot16-producing calls
  if(nEmit>=MAX_EMIT){ done=true; stopAll('max_emit'); return; }
  nEmit++;
  const tables = sp? readHex(sp, 0x300) : null;              // 3 schedule tables (sp,sp+0x100,sp+0x200)
  const rec={ t:'DUMP', n:nEmit, slot16:hit.v, winOff:hit.off, out:out,
              args: f?f.x:null, round0: f?f.round0:null,
              x9:x9.toString(), sp:sp?sp.toString():null, tables:tables };
  send(rec);
  if(nEmit>=MAX_EMIT){ done=true; stopAll('max_emit'); }
}

function stopAll(reason){
  for(const tid of followed){ try{ Stalker.unfollow(tid); }catch(e){} }
  try{ Stalker.flush(); }catch(e){}
  followed.clear();
  send({t:'stopped', reason:reason, nEmit:nEmit, nEntry:nEntry, nStore:nStore});
}

let excluded=false;
function excludeOthers(){
  if(excluded) return; excluded=true;
  let n=0; for(const m of Process.enumerateModules()){ if(m.name===SO) continue;
    try{ Stalker.exclude({base:m.base, size:m.size}); n++; }catch(e){} }
  send({t:'excluded', n:n});
}
function startFollow(){
  const tid=Process.getCurrentThreadId();
  if(followed.has(tid)) return;
  excludeOthers();
  followed.add(tid);
  send({t:'follow_start', tid:tid});
  Stalker.follow(tid, { transform:function(iterator){
    let insn;
    while((insn=iterator.next())!==null){
      const pc=insn.address;
      iterator.keep();
      if(!inLib(pc)) continue;
      const off=pc.sub(base).toInt32();
      if(off===ENTRY) iterator.putCallout(onEntry);
      else if(off===RB_TOP) iterator.putCallout(onRoundTop);
      else if(off===STORE) iterator.putCallout(onStore);
    }
  }});
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'stalk-dump installed base='+base});
  Interceptor.attach(base.add(MEMCPY), { onEnter(args){
    if(done) return;
    let sz; try{ sz=args[2].toInt32(); }catch(e){ return; } if(sz!==16) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra || ra.compare(lo)<0 || ra.compare(hi)>=0) return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let src,V; try{ src=args[1]; V=hx(src.readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10 && !wanted.has(V)) return;
    nRd++;
    wanted.add(V);
    if(nRd<=40) send({t:'rd', ord:nRd, val:V, known:KNOWN.indexOf(V)>=0});
    startFollow();
  }});
  setInterval(function(){ send({t:'mon', nRd:nRd, nEntry:nEntry, nStore:nStore, nEmit:nEmit, done:done}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
