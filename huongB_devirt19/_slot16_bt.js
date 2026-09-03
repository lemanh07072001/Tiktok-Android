// _slot16_bt.js — hook SM3, reconstruct #19 msg, on NONZERO slot16 capture native backtrace.
// Reveals the sign-pipeline call chain -> pick a Stalker anchor upstream of the producer write.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={}; const seen={}; let done=0;
  Interceptor.attach(base.add(SM3),{onEnter(){
    if(done>=3) return;
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot==='00'.repeat(16)||pr>=12||seen[slot]){ delete chain[tid]; return; }
    seen[slot]=1; done++;
    // SAFE caller chain: direct returnAddress + scan stack for return-addresses into libmetasec
    let ret=null; try{ ret=this.returnAddress; }catch(e){}
    const mod=Process.findModuleByName(SO); const lo=mod.base, hi=mod.base.add(mod.size);
    const chainRA=[];
    if(ret) chainRA.push(ret+' '+region(ret));
    try{
      const sp=this.context.sp;
      for(let off=0; off<0x800 && chainRA.length<20; off+=8){
        let v; try{ v=sp.add(off).readPointer(); }catch(e){ break; }
        if(v.compare(lo)>=0 && v.compare(hi)<0){ chainRA.push(v+' '+region(v)); }
      }
    }catch(e){}
    send({t:'bt', slot16:slot, tid:tid, mlen:mlen, ret:ret?ret.toString():null, chainRA:chainRA});
    delete chain[tid];
  }});
  send({t:'info',msg:'slot16-bt installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
