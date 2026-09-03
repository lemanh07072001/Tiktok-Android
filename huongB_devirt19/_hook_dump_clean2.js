// _hook_dump_clean2.js — fully clean dump: read the finished output AFTER all 4 store insns, at 0xa0fa0,
// where x9 still points at the output buffer and sp is still the frame base (tables intact).
//
// Why not 0xa0f90 (clean1's STORE): that IS `stp w16,w17,[x9,#8]`. Frida relocates the hooked store and its
// x16/x17 branch scratch bleeds into the store target, corrupting out[0],out[1] in memory (constant across
// messages -> the tell). out[2..7] stayed clean and already matched _compress 6/8. Reading at 0xa0fa0 (the
// first insn PAST the 4 stps, before `ldur x9,[x29,#-0x60]` reuses x9 and before `add sp,sp,#0x320`) yields
// a pristine 32B output and the 3 tables, with w16 already dead.
//
// Layout recap:
//   PRELOAD   0xa0de0  read iv=[x9+8,32] BEFORE the load (state still = input; not yet overwritten in place)
//   POSTSTORE 0xa0fa0  read out=[x9+8,32] + tables=[sp,0x300]; emit, pairing iv by tid.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const PRELOAD=0xa0de0, POSTSTORE=0xa0fa0;
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82',
  '70208dae6764a6a7800499a4d2bef595','851dbc7109471d9b56f8c9c29ca143db','051afb6b2a4b02cdb42d28ab0f81b736'];
const wanted=new Set(KNOWN);
let base=null, lo=null, hi=null, nPre=0, nPost=0, nRd=0, nEmit=0, done=false;
const MAX_EMIT=16;
const scratch=new Map();                 // tid -> {iv, ivFull, x9pre}

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent16(v){ if(!v)return 0; let z=0; for(let i=0;i<32;i+=2){ if(v.substr(i,2)==='00') z++; } return 16-z; }
function readHex(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function windows(out){ if(!out||out.length<64) return []; return [
  {off:0,v:out.substr(0,32)},{off:8,v:out.substr(16,32)},{off:16,v:out.substr(32,32)}]; }
function knownWin(out){ for(const w of windows(out)){ if(wanted.has(w.v)) return w; } return null; }
function stopAll(reason){ done=true; send({t:'stopped', reason:reason, nEmit:nEmit, nPre:nPre, nPost:nPost, nRd:nRd}); }

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'clean2 dump installed base='+base});

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

  // PRELOAD: input state (IV) before the load overwrites it in place
  try{ Interceptor.attach(base.add(PRELOAD), { onEnter(){
    if(done) return; nPre++;
    const tid=this.threadId; let x9; try{ x9=this.context.x9; }catch(e){ return; }
    let sc=scratch.get(tid); if(!sc){ sc={}; scratch.set(tid,sc); }
    sc.iv = x9? readHex(x9.add(8), 32) : null;
    sc.ivFull = x9? readHex(x9, 48) : null;
    sc.x9pre = x9? x9.toString() : null;
  }}); }catch(e){ send({t:'err', where:'preload', e:String(e)}); }

  // POSTSTORE: finished output + tables, all clean; emit
  try{ Interceptor.attach(base.add(POSTSTORE), { onEnter(){
    if(done) return; nPost++;
    const tid=this.threadId; let x9,sp; try{ x9=this.context.x9; sp=this.context.sp; }catch(e){ return; }
    const sc=scratch.get(tid)||{}; scratch.delete(tid);
    const out = x9? readHex(x9.add(8), 32) : null;
    const tables = sp? readHex(sp, 0x300) : null;
    const kw = knownWin(out);
    if(nEmit>=MAX_EMIT){ stopAll('max_emit'); return; }
    nEmit++;
    send({ t:'DUMP', n:nEmit, known: kw?kw.v:null, knownOff: kw?kw.off:null,
           iv: sc.iv||null, ivFull: sc.ivFull||null, x9pre: sc.x9pre||null, x9: x9?x9.toString():null,
           out: out, tables: tables });
    if(nEmit>=MAX_EMIT) stopAll('max_emit');
  }}); }catch(e){ send({t:'err', where:'poststore', e:String(e)}); }

  setInterval(function(){ send({t:'mon', nPre:nPre, nPost:nPost, nRd:nRd, nEmit:nEmit, done:done}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
