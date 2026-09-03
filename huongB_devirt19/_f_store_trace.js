// _f_store_trace.js — trace the STORES of a candidate producer program to find the slot16 write.
// Prior scans checked regfile/output-buffers (0 hit) but slot16 may be STORED to an address OUTSIDE the
// object-graph. Stalker-follow the program; callout on str/stp/stur; log (pc, target-addr, stored value).
// Flag any store whose value == a real slot16, or whose target is a header entry (tag 020102). Learn pool.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, SM3=0xa0748;
const TARGET=parseInt((typeof TGT!=='undefined')?TGT:'0x17c880',16);
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function regLE(v){ let h=v.toString(16); if(h.length>16)h=h.slice(-16); h=h.padStart(16,'0'); let b=''; for(let i=0;i<8;i++) b+=h.substr((7-i)*2,2); return b; }
let base=null, done=false, active=false; const pool={}; const stores=[]; let nstore=0;
function calloutStore(ctx){
  if(!active||nstore>=6000) return;
  let pc; try{ pc=ctx.pc; }catch(e){ return; }
  let pcrel; try{ pcrel=pc.sub(base).toInt32(); }catch(e){ return; }
  if(pcrel<0x52000||pcrel>=0x5d000) return; // VM handler region only
  try{
    const ins=Instruction.parse(pc); const mn=ins.mnemonic;
    if(mn!=='str'&&mn!=='stp'&&mn!=='stur') return;
    const ops=ins.opStr.split(',').map(s=>s.trim());
    let val=regLE(ctx[ops[0]]); if(mn==='stp') val+=regLE(ctx[ops[1]]);
    // target address: parse [xN, #off] or [xN]
    const mbr=ins.opStr.match(/\[(\w+)(?:,\s*#?(-?(?:0x)?[0-9a-f]+))?/);
    let tgt=null; if(mbr){ try{ const bv=ctx[mbr[1]]; const off=mbr[2]?parseInt(mbr[2]):0; tgt=bv.add(off); }catch(e){} }
    nstore++;
    stores.push({pc:'0x'+pcrel.toString(16), mn:mn, val:val, tgt:tgt?tgt.toString():null, tgtctx:tgt?hx(tgt.sub(16),16):null});
  }catch(e){}
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; const lo=base, hi=base.add(m.size); const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(done||active) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==TARGET) return; }catch(e){ return; }
    active=true; send({t:'start', prog:'0x'+TARGET.toString(16)});
    Stalker.follow(this.threadId,{ transform(iter){ let ins; while((ins=iter.next())!==null){ const mn=ins.mnemonic;
      if(mn==='str'||mn==='stp'||mn==='stur') iter.putCallout(calloutStore); iter.keep(); } }});
    this.following=true;
  }, onLeave(){
    if(!this.following) return; try{ Stalker.unfollow(this.threadId); Stalker.flush(); }catch(e){}
    active=false; done=true;
    send({t:'end', nstore:stores.length});
    const CH=300; for(let i=0;i<stores.length;i+=CH) send({t:'st', rows:stores.slice(i,i+CH)});
    send({t:'done'});
  }});
  setTimeout(function(){ send({t:'poollate', pool:Object.keys(pool)}); }, 25000);
  send({t:'info',msg:'f-store-trace installed target=0x'+TARGET.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
