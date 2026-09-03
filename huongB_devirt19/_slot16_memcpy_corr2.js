// _slot16_memcpy_corr2.js — v3b: correlate slot16 pool-WRITE, now including libc copies.
// v3 proved the write is NOT libmetasec's internal 0x172a50. Add libc memcpy/memmove/__memcpy_chk. Their RETURN
// ADDRESS is the caller = the libmetasec producer function. Filter recorded copies to dst in the slot16 POOL BAND
// so the ring stays clean and low-churn. If STILL no match, the producer stores slot16 directly (no copy) -> we
// then know to do a code-scoped Stalker. Pure Interceptor: stable.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
const POOL_LO=ptr('0x77e0000000'), POOL_HI=ptr('0x77f0000000');   // slot16 pool arena band (0x77e4e..0x77e51 seen)
let base=null, lo=null, hi=null, done=false;
let nCopy=0, nRd=0, nLibc=0;
const RING=8192;
const r_dst=new Array(RING), r_src=new Array(RING), r_sz=new Array(RING), r_ret=new Array(RING), r_val=new Array(RING), r_who=new Array(RING);
let ri=0, rc=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v)return 0; let pr=0; for(let i=0;i<Math.min(32,v.length);i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function retoff(ra){ if(!ra)return null; if(ra.compare(lo)>=0&&ra.compare(hi)<0) return 'SELF+0x'+ra.sub(base).toString(16); return ra.toString(); }
function inPool(p){ return p.compare(POOL_LO)>=0 && p.compare(POOL_HI)<0; }

function record(dst,src,sz,ra,who){
  let val=null; try{ val=hx(src.readByteArray(Math.min(sz,32))); }catch(e){}
  r_dst[ri]=dst; r_src[ri]=src; r_sz[ri]=sz; r_ret[ri]=retoff(ra); r_val[ri]=val; r_who[ri]=who;
  ri=(ri+1)&(RING-1); if(rc<RING) rc++;
}
function matchWrite(P){
  for(let k=0;k<rc;k++){
    const idx=(ri-1-k+RING)&(RING-1);
    const d=r_dst[idx]; if(!d) continue;
    const s=r_sz[idx]||0;
    if(d.compare(P)<=0 && P.compare(d.add(s))<0){
      return {dst:d.toString(), src:r_src[idx]?r_src[idx].toString():null, ret:r_ret[idx], val:r_val[idx], sz:s, who:r_who[idx], off:P.sub(d).toInt32(), back:k};
    }
  }
  return null;
}

function hookLibc(name){
  let p=null; try{ p=Module.findGlobalExportByName(name); }catch(e){}
  if(!p){ send({t:'libc_miss', name:name}); return; }
  Interceptor.attach(p, { onEnter(args){
    if(done)return;
    let dst,src,sz; try{ dst=args[0]; src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz<8||sz>128) return;
    if(!inPool(dst)) return;                 // only care about writes landing in the slot16 pool arena
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    nLibc++; record(dst,src,sz,ra,name);
  }});
  send({t:'libc_hooked', name:name, addr:p.toString()});
}

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  // libmetasec internal copy 0x172a50 : reader detection + record (any dst)
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done)return;
    let dst,src,sz; try{ dst=args[0]; src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz<8||sz>128) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    const roff=ra&&ra.compare(lo)>=0&&ra.compare(hi)<0 ? ra.sub(base).toString(16) : null;
    if(roff===READBUCKET.toString(16) && sz===16){
      nRd++;
      let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
      const w=matchWrite(src);
      send({t:'rd', ord:nRd, P:src.toString(), val:val, tid:this.threadId, ringN:rc, writeSite:w});
      if(nRd>=14){ done=true; send({t:'stopped', nRd:nRd, nCopy:nCopy, nLibc:nLibc}); }
      return;
    }
    // record internal copies that land in the pool too
    if(inPool(dst)){ nCopy++; record(dst,src,sz,ra,'meta0x172a50'); }
  }});
  // libc copy primitives (the producer likely writes the pool via one of these)
  hookLibc('memcpy'); hookLibc('memmove'); hookLibc('__memcpy_chk'); hookLibc('__memmove_chk');
  setInterval(function(){ send({t:'mon', nCopy:nCopy, nLibc:nLibc, nRd:nRd, ringN:rc}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
