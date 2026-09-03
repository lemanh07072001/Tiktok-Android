// _producer_wp.js v2 — WRITE-ONLY software watchpoint via page protection, reads the VALUE being
// stored (from the store instruction's source regs) to pinpoint the PRODUCER of a slot16 value.
// r-- window: reads pass, writes fault. On fault: parse ins@pc, read source reg(s) => written bytes;
// if slot16-like (learned pool match, or high-entropy no-tag) report {from=producer PC}. Re-protect
// pages (per-page cap) to keep watching past the header-frame memcpy writes.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const WIN=0x100000, FAULT_CAP=2400, PER_PAGE_CAP=10;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){} return 'anon?'; }
function regLE(v){ // NativePointer/UInt64 register -> little-endian 8-byte hex (memory order)
  let h=v.toString(16); if(h.length>16)h=h.slice(-16); h=h.padStart(16,'0');
  let b=''; for(let i=0;i<8;i++) b+=h.substr((7-i)*2,2); return b;
}
function slotLike(hexv){ // 16-byte hex: high-entropy, no 020102 tag, few zeros
  if(!hexv||hexv.length<32) return false; const v=hexv.slice(0,32);
  if(v.indexOf('020102000000')>=0) return false;
  let zero=0,set={}; for(let i=0;i<16;i++){ const b=v.substr(i*2,2); if(b==='00')zero++; set[b]=1; }
  return zero<=2 && Object.keys(set).length>=12;
}
let mod=null,mlo=null,mhi=null;
let armed=false, winLo=null, winHi=null, faults=0, stopped=false;
const seenPC={}; let nprod=0; const pageF={}; const pool={};
function reprotect(pg){ if(stopped) return; try{ Memory.protect(pg,0x1000,'r--'); }catch(e){} }
function installHandler(){
  Process.setExceptionHandler(function(d){
    try{
      if(stopped||!d.memory) return false;
      if(d.type!=='access-violation') return false;
      const acc=d.memory.address;
      if(!acc||acc.compare(winLo)<0||acc.compare(winHi)>=0) return false;
      faults++;
      if(d.memory.operation==='write'){
        const pc=d.context.pc;
        if(pc&&pc.compare(mlo)>=0&&pc.compare(mhi)<0){
          // read value being stored
          let val=null;
          try{ const ins=Instruction.parse(pc); const mn=ins.mnemonic;
            if(mn==='stp'||mn==='str'||mn==='stur'){
              const ops=ins.opStr.split(',').map(s=>s.trim());
              const r0=ops[0];
              if(mn==='stp'){ const r1=ops[1]; val=regLE(d.context[r0])+regLE(d.context[r1]); }
              else { val=regLE(d.context[r0]); }
            }
          }catch(e){}
          const matchPool = val && pool[val.slice(0,32)];
          const sl = val && slotLike(val);
          // DIAGNOSTIC: report first N in-module writes with their value (mark slotLike/pool)
          if(val && nprod<20){ const pcs=pc.toString();
            if(!seenPC[pcs]){ seenPC[pcs]=1; nprod++;
              send({t:'PROD', from:pcs, from_region:region(pc), addr:acc.toString(), val:val.slice(0,32), matchPool:!!matchPool, slotLike:!!sl, ins:(function(){try{const i=Instruction.parse(pc);return i.mnemonic+' '+i.opStr;}catch(e){return '?';}})()});
            }
          }
        }
      }
      const pg=acc.and(ptr('0xfffffffffffff000')); const pgs=pg.toString();
      pageF[pgs]=(pageF[pgs]||0)+1;
      try{ Memory.protect(pg,0x1000,'rw-'); }catch(e){}      // let this write proceed
      if(pageF[pgs]<PER_PAGE_CAP && faults<FAULT_CAP && !stopped){ setTimeout(function(){reprotect(pg);},0); }
      if(faults>=FAULT_CAP&&!stopped){ stopped=true; try{ Memory.protect(winLo,winHi.sub(winLo).toInt32(),'rw-'); }catch(e){} send({t:'info',msg:'fault-cap, unprotected'}); }
      return true;
    }catch(e){ return true; }
  });
}
let calls=0,taghits=0;
function install(){
  mod=Process.findModuleByName(SO); if(!mod) return false;
  const base=mod.base; mlo=base; mhi=base.add(mod.size); const chain={};
  // learn pool (SM3) for definitive value matching
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80){ return; }
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1;
    delete chain[tid];
  }});
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(armed) return;
    const len=a[2].toInt32(); if(len<16||len>32) return; calls++;
    const src=a[1]; let pre; try{ pre=hx(src.sub(16),16); }catch(e){ return; }
    if(!pre||pre.slice(0,12)!=='020102000000') return; taghits++;
    const r=Process.findRangeByAddress(src); if(!r) return;
    armed=true; installHandler();
    let lo=src.sub(WIN/2); if(lo.compare(r.base)<0) lo=r.base;
    let hi=lo.add(WIN); const rend=r.base.add(r.size); if(hi.compare(rend)>0) hi=rend;
    winLo=lo.and(ptr('0xfffffffffffff000')); winHi=hi;
    send({t:'armed', entry:src.toString(), win_lo:winLo.toString(), win_hi:winHi.toString(), poolsz:Object.keys(pool).length});
    try{ Memory.protect(winLo,winHi.sub(winLo).toInt32(),'r--'); }catch(e){ send({t:'err',msg:'protect:'+e}); }
  }});
  setTimeout(function(){ send({t:'dbg', calls:calls, taghits:taghits, armed:armed, faults:faults, nprod:nprod, poolsz:Object.keys(pool).length}); }, 25000);
  setTimeout(function(){ send({t:'dbg', calls:calls, taghits:taghits, armed:armed, faults:faults, nprod:nprod, poolsz:Object.keys(pool).length}); }, 55000);
  send({t:'info',msg:'producer-wp v2 installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
