// _correlate_seq.js — log the SEQUENCE of VM-invocation LRs before each nonzero #19,
// to identify the slot16-PRODUCER invocation (0x9ff1c = report-hash, producer is earlier).
'use strict';
const SO='libmetasec_ov.so', VM=0x52924, SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={}; const seq={};   // tid -> rolling last LRs
  Interceptor.attach(base.add(VM),{onEnter(){
    const tid=this.threadId; const off=this.context.lr.sub(base).toString(16);
    (seq[tid]=seq[tid]||[]).push('0x'+off); if(seq[tid].length>8) seq[tid].shift();
  }});
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot=''; let printable=0; for(let i=mlen-17;i<mlen-1;i++){ slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e) printable++; }
    // reject ASCII-query false positives (real crypto slot16 is ~random, not printable text)
    if(slot!=='00'.repeat(16) && printable<12){
      let qtail=f.slice(0,mlen-17); let isReg=(qtail.indexOf('ssmix=a')>=0&&qtail.indexOf('&item')<0);
      send({t:'sm3',tid:tid,slot16:slot,lrseq:(seq[tid]||[]).slice(),qhead:qtail.slice(0,50),reg:isReg});
    }
    delete chain[tid];
  }});
  send({t:'info',msg:'seq-correlate installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
