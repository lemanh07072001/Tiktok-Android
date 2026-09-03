// _slot16_flow.js — map the full copy flow of slot16.
// SM3 hook learns nonzero pool values. 0x172a50 (internal memcpy) catches EVERY copy whose
// src holds a learned value => src->dst chain. Earliest/deepest src = producer output buffer.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748, MEMCPY=0x172a50;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rdhx(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
const pool={}; const seenCopy={}; let ncopy=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  // learn pool from SM3
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1;
    delete chain[tid];
  }});
  // catch copies of pool values
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    const len=a[2].toInt32(); if(len<16||len>2048) return;
    const src=a[1]; let buf; try{ buf=new Uint8Array(ptr(src).readByteArray(Math.min(len,256))); }catch(e){ return; }
    for(let off=0; off+16<=buf.length; off++){
      let s=''; for(let i=0;i<16;i++) s+=('0'+buf[off+i].toString(16)).slice(-2);
      if(pool[s]){
        const srcAt=ptr(src).add(off);
        const key=s+'@'+region(srcAt);
        if(seenCopy[key]||ncopy>=24) return; seenCopy[key]=1; ncopy++;
        let ret=null; try{ ret=this.returnAddress; }catch(e){}
        const chainRA=[]; if(ret) chainRA.push(ret+' '+region(ret));
        try{ const sp=this.context.sp; for(let o=0;o<0x400 && chainRA.length<12;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
          if(v.compare(lo)>=0&&v.compare(hi)<0) chainRA.push(v+' '+region(v)); } }catch(e){}
        send({t:'copy', slot16:s, src:srcAt.toString(), src_region:region(srcAt), dst:a[0].toString(), dst_region:region(a[0]), len:len, off:off, before16:rdhx(srcAt.sub(16),16), after16:rdhx(srcAt.add(16),16), chainRA:chainRA});
        return;
      }
    }
  }});
  send({t:'info',msg:'slot16-flow installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
