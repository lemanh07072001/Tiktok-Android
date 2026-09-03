// _f_output.js — find which VM program OUTPUTS slot16 (= F, the producer).
// Candidates = programs common before every nonzero #19. For each candidate invocation, at onLeave
// capture its output buffers, push to a per-tid rolling list. On each nonzero #19 (slot16 extracted
// from query‖slot16‖'0'), scan the recent outputs for a buffer CONTAINING slot16 → that program = F.
'use strict';
const SO='libmetasec_ov.so', VM=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const CANDS=null; // ALL programs
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let emitted=0; const CAP=(typeof FO_CAP!=='undefined')?FO_CAP:12;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  const chain={}; const roll=[];   // GLOBAL rolling outputs (cross-tid)
  function grab(p,n,depth,acc){ const h=hx(p,n); if(h) acc.push(h); if(depth>0){ for(let i=0;i<Math.min(n/8,8);i++){ try{ const q=ptr(p).add(i*8).readPointer(); if(!q.isNull()) grab(q,32,depth-1,acc); }catch(e){} } } }
  Interceptor.attach(base.add(VM),{
    onEnter(a){
      let x0=a[0];
      try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; }catch(e){ return; }
      const off=x0.sub(base).toInt32();
      // capture ALL programs
      this.rec=true; this.prog='0x'+off.toString(16); this.x1=a[1]; this.x4=a[4];
    },
    onLeave(){
      if(!this.rec) return;
      const bufs=[];
      let h=hx(this.x4,64); if(h)bufs.push(h);
      try{ h=hx(ptr(this.x4).readPointer(),48); if(h)bufs.push(h);}catch(e){}
      h=hx(this.x1,0x40); if(h)bufs.push(h);
      roll.push({prog:this.prog,bufs:bufs});
      if(roll.length>1200) roll.shift();
    }
  });
  Interceptor.attach(base.add(SM3),{onEnter(){
    if(emitted>=CAP) return;
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],Ln=a.length; if(Ln<9) return;
    let bl=0; for(let i=Ln-8;i<Ln;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<Ln)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot==='00'.repeat(16)||pr>=12){ delete chain[tid]; return; }
    // scan GLOBAL rolling outputs for slot16
    const hits={};
    for(let k=roll.length-1;k>=0;k--){
      const r=roll[k];
      for(let bi=0;bi<r.bufs.length;bi++){
        if(r.bufs[bi].indexOf(slot)>=0){ hits[r.prog]=(hits[r.prog]||0)+1; }
      }
    }
    emitted++;
    send({t:'nz', tid:tid, slot16:slot, mlen:mlen, qhead:String.fromCharCode.apply(null,a.slice(0,40)), hits:hits});
    delete chain[tid];
  }});
  send({t:'info',msg:'f-output installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
