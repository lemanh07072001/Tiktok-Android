// _vm_trace_cluster.js — trace the WHOLE crypto-cluster execution starting at the first 0x186600
// invocation (SM3-IV) through the compression, logging register-file (x24) deltas at every VM `br`.
// Learn pool (SM3). Offline: reconstruct regfiles + check any 16-byte window == a pool slot16
// => the step/program where slot16 materializes in the register file (the producer).
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, SM3=0xa0748, TRIGGER=0x186600, CAP=8000;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
let started=false, active=false, base=null, done=false;
let prev=null; const trace=[]; let step=0; const pool={};
function delta(cur){ const ch=[]; if(!prev){ for(let r=0;r<32;r++){ let v=''; for(let i=0;i<8;i++) v+=('0'+cur[r*8+i].toString(16)).slice(-2); ch.push([r,v]); } return ch; }
  for(let r=0;r<32;r++){ let diff=false; for(let i=0;i<8;i++) if(cur[r*8+i]!==prev[r*8+i]){ diff=true; break; }
    if(diff){ let v=''; for(let i=0;i<8;i++) v+=('0'+cur[r*8+i].toString(16)).slice(-2); ch.push([r,v]); } }
  return ch; }
function finish(){ if(done) return; done=true; active=false;
  try{ Stalker.unfollow(); Stalker.flush(); }catch(e){}
  send({t:'end', steps:step, pool:Object.keys(pool)});
  const CH=350; for(let i=0;i<trace.length;i+=CH){ send({t:'tr', from:i, rows:trace.slice(i,i+CH)}); }
  send({t:'done'});
}
function calloutBr(ctx){
  if(!active||step>=CAP) { if(step>=CAP&&!done) finish(); return; }
  let pcrel; try{ pcrel=ctx.pc.sub(base).toInt32(); }catch(e){ return; }
  if(pcrel<0x52000||pcrel>=0x5d000) return;
  let cur; try{ cur=new Uint8Array(ptr(ctx.x24).readByteArray(256)); }catch(e){ return; }
  if(!cur) return;
  const ch=delta(cur); prev=cur;
  trace.push({s:step, pc:'0x'+pcrel.toString(16), d:ch}); step++;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; const lo=base, hi=base.add(m.size); const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(started||done) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==TRIGGER) return; }catch(e){ return; }
    started=true; active=true; prev=null;
    send({t:'start', trigger:'0x'+TRIGGER.toString(16), tid:this.threadId});
    Stalker.follow(this.threadId,{ transform(iter){ let ins; while((ins=iter.next())!==null){ if(ins.mnemonic==='br'||ins.mnemonic==='blr') iter.putCallout(calloutBr); iter.keep(); } }});
  }});
  setTimeout(finish, 12000); // stop trace 12s after install regardless
  send({t:'info',msg:'vm-trace-cluster installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
