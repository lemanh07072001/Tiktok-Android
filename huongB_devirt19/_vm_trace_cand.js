// _vm_trace600.js — dynamic trace of ONE invocation of VM program 0x186600 via Stalker.
// The interpreter (0x52924) uses threaded dispatch (per-handler `br`); regfile base = x24 (callee-saved).
// Follow the thread during the first 0x186600 interp-call; callout at each `br`; log the DELTA of the
// 32-register file (256B @x24) per step => the cipher's data-flow trace (reg = f(reg,reg) sequence).
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, TARGET=0x17c880, CAP=4000;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
let done=false, active=false, rfBase=null, progBase=null, base=null;
let prev=null; const trace=[]; let step=0;
function readRFfrom(p){ try{ return new Uint8Array(ptr(p).readByteArray(256)); }catch(e){ return null; } }
function delta(cur){ // 8-byte-register granularity changes vs prev
  const ch=[]; if(!prev){ for(let r=0;r<32;r++){ let v=''; for(let i=0;i<8;i++) v+=('0'+cur[r*8+i].toString(16)).slice(-2); ch.push([r,v]); } return ch; }
  for(let r=0;r<32;r++){ let diff=false; for(let i=0;i<8;i++) if(cur[r*8+i]!==prev[r*8+i]){ diff=true; break; }
    if(diff){ let v=''; for(let i=0;i<8;i++) v+=('0'+cur[r*8+i].toString(16)).slice(-2); ch.push([r,v]); } }
  return ch;
}
function calloutBr(ctx){
  if(!active) return;
  if(step>=CAP){ try{ Stalker.unfollow(); }catch(e){} active=false; return; }
  // log ALL br PCs to verify self-containment (no gate); mark whether in VM region
  let pcrel, inmod=false, invm=false;
  try{ const m=Process.findModuleByAddress(ctx.pc); inmod=!!m; if(m) pcrel='0x'+ctx.pc.sub(m.base).toString(16); else pcrel=ctx.pc.toString(); }catch(e){ pcrel=ctx.pc.toString(); }
  let pr=-1; try{ pr=ctx.pc.sub(base).toInt32(); invm=(pr>=0x52000&&pr<0x5d000); }catch(e){}
  let ch=[]; if(invm){ const cur=readRFfrom(ctx.x24); if(cur){ ch=delta(cur); prev=cur; } }
  trace.push({s:step, pc:pcrel, inmod:inmod, invm:invm, d:ch});
  step++;
}
const pool={}; const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx2(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; const lo=base, hi=base.add(m.size); const chainSM={};
  Interceptor.attach(base.add(0xa0748),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx2(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chainSM[tid]=Array.from(inp); else if(chainSM[tid]){ for(let i=0;i<64;i++) chainSM[tid].push(inp[i]); } else return;
    const a=chainSM[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chainSM[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chainSM[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(done||active) return;
    let x0=a[0]; try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==TARGET) return; }catch(e){ return; }
    // this is a 0x186600 invocation. x24 regfile is set inside; grab from context now (callee-saved)
    rfBase=this.context.x24; progBase=x0; active=true; prev=null; step=0;
    // capture inputs
    let inflat=null; try{ inflat=hx(a[1].readByteArray(64)); }catch(e){}
    let rf0=null; try{ rf0=hx(rfBase.readByteArray(256)); }catch(e){}
    send({t:'start', prog:'0x'+TARGET.toString(16), rfBase:rfBase.toString(), x1:a[1].toString(), inflat:inflat, rf0:rf0});
    const brAddr={};
    Stalker.follow(this.threadId,{ transform(iter){ let ins;
      while((ins=iter.next())!==null){ if(ins.mnemonic==='br'||ins.mnemonic==='blr'){ iter.putCallout(calloutBr); } iter.keep(); }
    }});
    this.following=true;
  }, onLeave(){
    if(!this.following) return;
    try{ Stalker.unfollow(this.threadId); Stalker.flush(); }catch(e){}
    active=false; done=true;
    let rfEnd=null; try{ rfEnd=hx(rfBase.readByteArray(256)); }catch(e){}
    send({t:'end', steps:step, rfEnd:rfEnd, pool:Object.keys(pool)});
    // send trace in chunks
    const CH=400; for(let i=0;i<trace.length;i+=CH){ send({t:'tr', from:i, rows:trace.slice(i,i+CH)}); }
    send({t:'done'});
  }});
  setTimeout(function(){ send({t:'poollate', pool:Object.keys(pool)}); }, 18000);
  setTimeout(function(){ send({t:'poollate', pool:Object.keys(pool)}); }, 40000);
  send({t:'info',msg:'vm-trace600 installed (Stalker br-callout, regfile@x24)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
