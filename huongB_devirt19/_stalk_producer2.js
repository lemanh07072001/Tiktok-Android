// _stalk_producer2.js — ADDRESS-match producer localization (v2).
// v1 lesson: value-match on wide stores FAILED (nStores froze while reads continued). The producer either
// assembles slot16 via narrow str-x (8B) stores, or computes in scratch then memcpy's into the pool
// (memcpy=libc, Stalker-excluded, invisible). So:
//   - instrument stp + str/stur(x-GPR) + str/stur(q-SIMD), NOT gated on value.
//   - record a RING of recent heap writes {addr, pc, mnem, tid, seq} (stack spills excluded).
//   - at the reader 0xa0440 we learn src=P (pool addr of slot16). ADDRESS-match: any recorded write whose
//     dest lands in [P-8, P+24) is a producer-store candidate -> report its PC. Address is invariant to how
//     many pieces the 16 bytes were assembled from.
// Follow stays reader-anchored (cheap: Stalker off until first real slot16). To beat the "producer ran before
// follow" timing, the DRIVER triggers many lifecycle bursts AFTER follow starts, so later productions are watched.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null;
let nRd=0, nStores=0, nCallouts=0, nHits=0, done=false;
const followed=new Set();
const RING=65536;                         // recent heap-write ring
const wa_addr=new Array(RING), wa_off=new Array(RING), wa_mn=new Array(RING), wa_tid=new Array(RING);
let wi=0, wcount=0, seq=0;
const wanted=new Set();                    // slot16 values learned at reader (value-match fallback)
const producers=[];                        // confirmed {ord, val, P, pc, mnem, dist}
const PTR_LO=ptr('0x1000'), PTR_HI=ptr('0x8000000000');
const MAX_CALLOUTS=6000000;

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v)return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function inLib(p){ return p.compare(lo)>=0 && p.compare(hi)<0; }
function readReg(ctx,name){ if(name==='x29')name='fp'; else if(name==='x30')name='lr'; else if(name==='wsp'||name==='sp')name='sp'; try{return ctx[name];}catch(e){return null;} }
function memDest(insn){ let mem=null; for(const op of insn.operands){ if(op.type==='mem'){mem=op.value;break;} } if(!mem||!mem.base)return null; return {base:mem.base, disp:(mem.disp||0)}; }

// return #bytes this store writes (only widths we instrument), else 0
function storeBytes(insn){
  const m=insn.mnemonic;
  if(m==='stp'||m==='stnp'){ for(const op of insn.operands){ if(op.type==='reg'){ const r=op.value; if(/^[qv]/.test(r))return 32; if(/^x|^d/.test(r))return 16; } } return 16; }
  if(m==='str'||m==='stur'){ for(const op of insn.operands){ if(op.type==='reg'){ const r=op.value; if(/^[qv]/.test(r))return 16; if(/^x|^d/.test(r))return 8; } } return 0; } // skip w/s/b/h (too noisy, 4B)
  return 0;
}

function stopAll(reason){
  for(const tid of followed){ try{ Stalker.unfollow(tid); }catch(e){} }
  try{ Stalker.flush(); }catch(e){}
  followed.clear();
  send({t:'unfollow', reason:reason, nStores:nStores, nCallouts:nCallouts, producers:producers});
}

function makeCallout(destBase, destDisp, off, mnem){
  return function(context){
    if(done) return;
    nCallouts++;
    let addr=readReg(context,destBase); if(!addr) { if(nCallouts>=MAX_CALLOUTS)stopAll('max'); return; }
    if(destDisp) addr=addr.add(destDisp);
    if(addr.compare(PTR_LO)<0 || addr.compare(PTR_HI)>=0){ if(nCallouts>=MAX_CALLOUTS)stopAll('max'); return; }
    // exclude stack spills: skip writes within the current frame band
    const sp=readReg(context,'sp');
    if(sp && addr.compare(sp.sub(0x2000))>=0 && addr.compare(sp.add(0x10000))<0){ if(nCallouts>=MAX_CALLOUTS)stopAll('max'); return; }
    // record into ring
    wa_addr[wi]=addr; wa_off[wi]=off; wa_mn[wi]=mnem; wa_tid[wi]=Process.getCurrentThreadId();
    wi=(wi+1)&(RING-1); if(wcount<RING) wcount++;
    nStores++;
    if(nCallouts>=MAX_CALLOUTS)stopAll('max');
  };
}

let excluded=false;
function excludeOthers(){
  if(excluded)return; excluded=true; let n=0;
  for(const m of Process.enumerateModules()){ if(m.name===SO)continue; try{ Stalker.exclude({base:m.base,size:m.size}); n++; }catch(e){} }
  send({t:'excluded', n:n});
}
function startFollow(){
  const tid=Process.getCurrentThreadId();
  if(followed.has(tid))return;
  excludeOthers(); followed.add(tid);
  send({t:'follow_start', tid:tid, nFollowed:followed.size});
  Stalker.follow(tid, { transform:function(iterator){
    let insn;
    while((insn=iterator.next())!==null){
      const pc=insn.address;
      if(inLib(pc) && storeBytes(insn)>0){
        const d=memDest(insn);
        iterator.keep();
        if(d && !/^(sp|wsp|fp|x29)$/.test(d.base)){
          iterator.putCallout(makeCallout(d.base, d.disp, '0x'+pc.sub(base).toString(16), insn.mnemonic));
        }
        continue;
      }
      iterator.keep();
    }
  }});
}

// ADDRESS-match: find recorded writes landing in [P-8, P+24)
function addrMatch(P){
  const lo2=P.sub(8), hi2=P.add(24), hits=[];
  const seen=new Set();
  for(let k=0;k<wcount;k++){
    const a=wa_addr[k]; if(!a)continue;
    if(a.compare(lo2)>=0 && a.compare(hi2)<0){
      const key=wa_off[k]; if(seen.has(key))continue; seen.add(key);
      hits.push({off:wa_off[k], mnem:wa_mn[k], addr:a.toString(), tid:wa_tid[k]});
    }
  }
  return hits;
}

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(MEMCPY), { onEnter(args){
    if(done)return;
    let sz; try{ sz=args[2].toInt32(); }catch(e){return;} if(sz!==16)return;
    let ra; try{ ra=this.returnAddress; }catch(e){return;}
    if(!ra || ra.compare(lo)<0 || ra.compare(hi)>=0)return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16))return;
    let src,V; try{ src=args[1]; V=hx(src.readByteArray(16)); }catch(e){return;}
    if(ent(V)<10 && !wanted.has(V))return;
    nRd++; wanted.add(V);
    const hits=addrMatch(src);
    send({t:'rd', ord:nRd, P:src.toString(), val:V, tid:Process.getCurrentThreadId(), following:followed.size, ringN:wcount, match:hits});
    if(hits.length && !done){
      for(const h of hits) producers.push({ord:nRd, val:V, P:src.toString(), off:h.off, mnem:h.mnem});
      // don't stop immediately; collect a few to disambiguate the real final-store PC
      if(producers.length>=6){ done=true; send({t:'PRODUCER_CANDIDATES', producers:producers}); stopAll('enough'); }
    }
    startFollow();
  }});
  setInterval(function(){ send({t:'mon', nRd:nRd, nFollowed:followed.size, nStores:nStores, nCallouts:nCallouts, ringN:wcount, nProd:producers.length}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
