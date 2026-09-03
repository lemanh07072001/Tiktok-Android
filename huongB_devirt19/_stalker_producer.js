// _stalker_producer.js — Route B CORE: Stalker store-trace to catch the slot16 producer's STORE.
// Stalker follows EXECUTION => not blocked by fresh-alloc/no-HW-wp. Anchor at seed-gen return
// (producer consumes seed right after); record stp/str stores whose target is in the keystore arena
// range (0x7e..; excludes stack 0x7b../scudo 0x7d..). Match recorded stores to slot16 (from serializer).
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, SEEDGEN=0x10ac2c;
const ALO=ptr('0x7e0000000000'), AHI=ptr('0x7f0000000000');
let base=null, lo, hi, following=false, followTid=0;
const stpInfo={};                 // pc(str) -> {reg, off, pair}
const ring=[]; const RINGMAX=6000;
function reg64(ctx,name){ try{ return ctx[name]; }catch(e){ return ptr(0); } }
function onStore(ctx){
  const pcs=ctx.pc.toString(); const info=stpInfo[pcs]; if(!info) return;
  let tgt; try{ tgt=reg64(ctx,info.reg).add(info.off); }catch(e){ return; }
  if(tgt.compare(ALO)<0 || tgt.compare(AHI)>=0) return;   // arena range only
  let v; try{ v=new Uint8Array(tgt.readByteArray(16)); }catch(e){ return; }
  let hexs=''; for(let i=0;i<16;i++) hexs+=('0'+v[i].toString(16)).slice(-2);
  ring.push({pc:'0x'+ctx.pc.sub(base).toString(16), tgt:tgt.toString(), val16:hexs});
  if(ring.length>RINGMAX){ ring.shift(); }
}
function decodeStp(addr){
  try{
    const ins=Instruction.parse(addr);
    if(ins.mnemonic!=='stp' && ins.mnemonic!=='str' && ins.mnemonic!=='stur') return null;
    const ops=ins.operands;
    // last operand = memory {base, disp}
    const mem=ops[ops.length-1];
    if(!mem || mem.type!=='mem') return null;
    const b=mem.value.base; const disp=mem.value.disp||0;
    if(!b) return null;
    return {reg:b, off:disp, pair:ins.mnemonic==='stp'};
  }catch(e){ return null; }
}
function transform(iterator){
  let insn;
  while((insn=iterator.next())!==null){
    if(insn.mnemonic==='stp'||insn.mnemonic==='str'||insn.mnemonic==='stur'){
      const d=decodeStp(insn.address);
      if(d){ stpInfo[insn.address.toString()]={reg:d.reg,off:d.off,pair:d.pair}; iterator.putCallout(onStore); }
    }
    iterator.keep();
  }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  // anchor: seed-gen returns -> start following the producer window
  Interceptor.attach(base.add(SEEDGEN),{onLeave(){
    if(following) return; following=true; followTid=this.threadId;
    try{ Stalker.follow(this.threadId,{transform:transform}); send({t:'follow',tid:this.threadId}); }
    catch(e){ send({t:'err',msg:'follow '+e}); following=false; }
  }});
  // serializer reached -> we have slot16; stop + dump
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(a[2].toInt32()!==16) return;
    let ra=null; try{ra=this.returnAddress;}catch(e){}
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!=='a0440') return;
    let s=''; try{ const u=new Uint8Array(a[1].readByteArray(16)); for(let i=0;i<16;i++) s+=('0'+u[i].toString(16)).slice(-2); }catch(e){ return; }
    if(s==='00'.repeat(16)) return;
    // search ring for stores that wrote this slot16
    const hits=ring.filter(r=>r.val16===s);
    send({t:'result', slot16:s, ringlen:ring.length, nhits:hits.length, hits:hits.slice(-8),
          sampleArena: ring.slice(-6)});
    if(following){ try{Stalker.unfollow(followTid); Stalker.flush();}catch(e){} following=false; }
  }});
  send({t:'info',msg:'stalker-producer installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
