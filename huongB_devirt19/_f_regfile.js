// _f_regfile.js — check whether slot16 appears in a program's REGFILE (@x24) at onLeave.
// x24 = VM regfile base (set at interp entry, callee-saved). Prior output-scan read x4/x1 only and
// missed it. Here: for candidate programs, capture regfile(256B) at onLeave + push to global roll;
// on each nonzero #19 (slot16 from query‖slot16‖'0'), scan roll → which program's regfile holds slot16.
'use strict';
const SO='libmetasec_ov.so', VM=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
// candidates: upstream + marshaller + report cluster (regfile digest could be anywhere). keep modest.
const CANDS={};[0x17c880,0x18f430,0x191f40,0x184780,0x190140,0x18fa80,0x17de80,0x17e530,0x1814f0].forEach(x=>CANDS[x]=1);
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let emitted=0; const CAP=(typeof FR_CAP!=='undefined')?FR_CAP:14;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  const chain={}; const roll=[];
  Interceptor.attach(base.add(VM),{
    onEnter(a){
      let x0=a[0];
      try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; }catch(e){ return; }
      const off=x0.sub(base).toInt32();
      if(!CANDS[off]) return;
      this.rec=true; this.prog='0x'+off.toString(16); this.x24=this.context.x24;
    },
    onLeave(){
      if(!this.rec) return;
      const rf=hx(this.x24,256);
      if(!rf) return;
      // ALSO deref each regfile 8-byte entry that looks like a pointer, read 64B (crypto buffer may live there)
      let derefs='';
      try{
        const u=new Uint8Array(ptr(this.x24).readByteArray(256));
        for(let r=0;r<32;r++){
          let lo=0; for(let i=0;i<6;i++) lo+=u[r*8+i]*Math.pow(256,i);
          const hib=u[r*8+7];
          if(hib===0x73||hib===0x74||hib===0x75||hib===0x76||hib===0x7f||hib===0x00){
            try{ const h=hx(ptr(this.x24).add(r*8).readPointer(),64); if(h) derefs+=h; }catch(e){}
          }
        }
      }catch(e){}
      roll.push({prog:this.prog,rf:rf,dr:derefs}); if(roll.length>400) roll.shift();
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
    // also test slot16 byteswapped-per-4 (VM stores state byteswapped sometimes)
    const bs=slot.match(/../g).reverse().join('');
    const hits={};
    for(let k=roll.length-1;k>=0;k--){
      const r=roll[k];
      if(r.rf.indexOf(slot)>=0){ hits[r.prog+':rf']=(hits[r.prog+':rf']||0)+1; }
      if(r.rf.indexOf(bs)>=0){ hits[r.prog+':rfrev']=(hits[r.prog+':rfrev']||0)+1; }
      if(r.dr&&r.dr.indexOf(slot)>=0){ hits[r.prog+':buf']=(hits[r.prog+':buf']||0)+1; }
      if(r.dr&&r.dr.indexOf(bs)>=0){ hits[r.prog+':bufrev']=(hits[r.prog+':bufrev']||0)+1; }
    }
    emitted++;
    send({t:'nz', slot16:slot, mlen:mlen, hits:hits, rollN:roll.length});
    delete chain[tid];
  }});
  send({t:'info',msg:'f-regfile installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
