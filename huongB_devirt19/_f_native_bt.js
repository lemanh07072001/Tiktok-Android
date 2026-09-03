'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let emitted=0; const CAP=(typeof BT_CAP!=='undefined')?BT_CAP:6;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  function rel(a){ try{ if(a.compare(lo)>=0&&a.compare(hi)<0) return '0x'+a.sub(base).toString(16); }catch(e){} return a.toString(); }
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
    const bt=Thread.backtrace(this.context, Backtracer.FUZZY).map(rel);
    emitted++;
    send({t:'nz', slot16:slot, bt:bt});
    delete chain[tid];
  }});
  send({t:'info',msg:'native-bt installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
