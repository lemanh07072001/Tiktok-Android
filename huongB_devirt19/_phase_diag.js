// _phase_diag.js — map tid + ordering of key native events per heartbeat (no Stalker).
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748, MEMCPY=0x172a50, SEEDGEN=0x10ac2c, FCALL=0x1384e4, ORCH=0x1864f0;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hxab(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
let base=null,lo,hi,seq=0; const chain={};
function ev(tag,tid,extra){ send({t:'ev', seq:++seq, tag:tag, tid:tid, extra:extra||null}); }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  try{ Interceptor.attach(base.add(SEEDGEN),{onLeave(r){ ev('seedgen', this.threadId, 'ret='+r.toInt32()); }}); }catch(e){ ev('hookfail','seedgen '+e); }
  try{ Interceptor.attach(base.add(FCALL),{onEnter(){ ev('Fcall', this.threadId); }}); }catch(e){ ev('hookfail','F '+e); }
  try{ Interceptor.attach(base.add(ORCH),{onEnter(){ ev('orch', this.threadId); }}); }catch(e){ ev('hookfail','orch '+e); }
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(a[2].toInt32()!==16) return; let ra=null; try{ra=this.returnAddress;}catch(e){}
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!=='a0440') return;
    let s=''; try{const u=new Uint8Array(a[1].readByteArray(16)); for(let i=0;i<16;i++)s+=('0'+u[i].toString(16)).slice(-2);}catch(e){return;}
    ev('serialize16', this.threadId, s);
  }});
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hxab(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE){ chain[tid]=Array.from(inp); ev('sm3_iv',tid); }
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot='',pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    delete chain[tid];
    if(slot!=='00'.repeat(16)&&pr<12) ev('SM3_slot16', tid, slot);
  }});
  send({t:'info',msg:'phase-diag installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
