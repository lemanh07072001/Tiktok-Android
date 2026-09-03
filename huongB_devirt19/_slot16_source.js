// _slot16_source.js — find WHERE slot16 is stored (the real source), non-perturbing-ish.
// Hook concat 0x150348 (combines query+slot16 for #19). Scan args + their derefs for a 16-byte pool slot16.
// Report the SOURCE address + which mapping (module/file) it lives in => that's where slot16 really comes from.
'use strict';
const SO='libmetasec_ov.so', CONCAT=0x150348, SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){} return 'anon?'; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const pool={}; let n=0;
  // learn the pool from #19 SM3 first
  const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80){return;}
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1;
    delete chain[tid];
  }});
  Interceptor.attach(base.add(CONCAT),{onEnter(){
    if(n>=12) return; const c=this.context;
    // scan x0..x5 + their derefs (2 levels) for a 16-byte value in pool
    const regs=['x0','x1','x2','x3','x4','x5'];
    for(let ri=0;ri<regs.length;ri++){ let base0=c[regs[ri]];
      for(let lvl=0;lvl<2;lvl++){
        const d=rd(base0,16); if(d && pool[d]){ n++; send({t:'src', slot16:d, via:regs[ri]+(lvl?'->deref':''), addr:base0.toString(), region:region(base0)}); }
        try{ base0=base0.readPointer(); }catch(e){ break; }
      }
    }
  }});
  send({t:'info',msg:'slot16-source installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
