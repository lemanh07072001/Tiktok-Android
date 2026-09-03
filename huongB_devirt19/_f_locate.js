// _f_locate.js — locate the per-request slot16 PRODUCER (F).
// slot16 is embedded in the #19 message (query‖slot16(16B)‖'0') hashed by native SM3 0xa0748.
// F runs per-request shortly before #19. Record, per tid, the rolling sequence of VM program-ids
// (x0-base at interp entry 0x52924). On each NONZERO slot16 #19, emit slot16 + full query + the
// program-id sequence that preceded it → the producer program is among them.
'use strict';
const SO='libmetasec_ov.so', VM=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const WIN=parseInt((typeof FL_WIN!=='undefined')?FL_WIN:80,10);
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
let emitted=0; const CAP=(typeof FL_CAP!=='undefined')?FL_CAP:12;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  const chain={}, seq={};   // tid -> reconstructed #19 msg / rolling program list
  Interceptor.attach(base.add(VM),{onEnter(a){
    const tid=this.threadId;
    let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; }catch(e){ return; }
    const off='0x'+x0.sub(base).toString(16);
    const L=(seq[tid]=seq[tid]||[]); L.push(off); if(L.length>WIN) L.shift();
  }});
  Interceptor.attach(base.add(SM3),{onEnter(){
    if(emitted>=CAP) return;
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80){ return; }
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot==='00'.repeat(16)||pr>=12){ delete chain[tid]; return; }
    // reconstruct full query text (bytes 0..mlen-17)
    let q=''; for(let i=0;i<mlen-17;i++) q+=String.fromCharCode(a[i]);
    emitted++;
    send({t:'nz', tid:tid, slot16:slot, mlen:mlen, query:q, progseq:(seq[tid]||[]).slice()});
    delete chain[tid];
  }});
  send({t:'info',msg:'f-locate installed win='+WIN});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
