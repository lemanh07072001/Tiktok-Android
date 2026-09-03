// _vm_enum.js — enumerate VM programs run by interpreter 0x52924 during nonzero-slot16 init.
// Log distinct program pointers (x0, offset from base) + call counts + first bytes of each program.
// Also learn pool (SM3) so we can timestamp when the first nonzero slot16 appears and see which
// programs ran before it. Foundation for picking the producer VM program to devirt.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){} return 'anon?'; }
let t0=Date.now();
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  const progs={}; let total=0; let firstSlotT=null; const beforeSlot={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12 && firstSlotT===null){ firstSlotT=Date.now()-t0;
      // snapshot which programs ran before the first nonzero slot16
      for(const k in progs) beforeSlot[k]=progs[k].n;
      send({t:'firstslot', ms:firstSlotT, slot16:slot, progs_before:Object.keys(beforeSlot).length});
    }
    delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    total++;
    const x0=a[0];
    let key; try{ key=x0.compare(lo)>=0&&x0.compare(hi)<0 ? '0x'+x0.sub(base).toString(16) : x0.toString(); }catch(e){ return; }
    if(!progs[key]){ progs[key]={n:0, first_ms:Date.now()-t0, bytes:hx(x0,256), region:region(x0)}; }
    progs[key].n++;
  }});
  // periodic dump of the program landscape
  function dump(tag){ const arr=Object.keys(progs).map(k=>({prog:k, n:progs[k].n, first_ms:progs[k].first_ms, before_first_slot:beforeSlot[k]!==undefined, bytes:progs[k].bytes})).sort((a,b)=>a.first_ms-b.first_ms);
    send({t:'landscape', tag:tag, total_vm_calls:total, distinct:arr.length, firstSlotT:firstSlotT, progs:arr.slice(0,60)}); }
  setTimeout(function(){ dump('8s'); }, 8000);
  setTimeout(function(){ dump('20s'); }, 20000);
  send({t:'info',msg:'vm-enum installed (interp 0x52924)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
