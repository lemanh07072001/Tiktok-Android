// _slot16_memcpy_corr.js — v3: memcpy-correlation to localize the slot16 pool-WRITE site (producer's final copy).
// v1 value-match & v2 str-x address-match both failed/hung. Insight: run1 saw ZERO stores into the pool band
// (0x77e5xxxx) during the burst — every wide store was SM3 scratch (0x752c07xx). So slot16 lands in the pool via
// a COPY, not inline stores. The read side already uses libmetasec's internal copy 0x172a50 (returns to 0xa0440).
// If the WRITE side uses the same primitive, then for each reader (src=P) there is an EARLIER 0x172a50 call with
// dst in [P,P+size) -> its return-address = the producer's pool-write call site; its src = the scratch buffer where
// the ARX computed slot16. Pure Interceptor: stable, no Stalker.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, done=false;
let nCopy=0, nRd=0;
const RING=4096;
const r_dst=new Array(RING), r_src=new Array(RING), r_sz=new Array(RING), r_ret=new Array(RING), r_val=new Array(RING), r_tid=new Array(RING);
let ri=0, rc=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v)return 0; let pr=0; for(let i=0;i<Math.min(32,v.length);i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function retoff(ra){ if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0) return null; return '0x'+ra.sub(base).toString(16); }

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done)return;
    let dst,src,sz; try{ dst=args[0]; src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz<8 || sz>128) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ ra=null; }
    const roff=retoff(ra);
    // read up to 32 bytes of source value for logging/entropy
    let val=null; try{ val=hx(src.readByteArray(Math.min(sz,32))); }catch(e){}

    // ---- READER path: this is the consume-copy of slot16 (ret==0xa0440, size 16) ----
    if(roff==='0x'+READBUCKET.toString(16) && sz===16){
      nRd++;
      const P=src;
      // scan ring backward for the most-recent copy whose dst covers P (the producer's pool-write)
      let found=null, foff=null;
      for(let k=0;k<rc;k++){
        const idx=(ri-1-k+RING)&(RING-1);
        const d=r_dst[idx]; if(!d) continue;
        const s=r_sz[idx]||0;
        if(d.compare(P)<=0 && P.compare(d.add(s))<0){
          found={dst:d.toString(), src:r_src[idx]?r_src[idx].toString():null, ret:r_ret[idx], val:r_val[idx], sz:s, tid:r_tid[idx], back:k};
          foff=P.sub(d).toInt32();
          break;
        }
      }
      send({t:'rd', ord:nRd, P:P.toString(), val:val, tid:this.threadId, ringN:rc,
            writeSite: found, offInDst: foff});
      if(nRd>=12){ done=true; send({t:'stopped', nRd:nRd, nCopy:nCopy}); }
      return;
    }

    // ---- record every other libmetasec-internal copy into the ring (candidate producer write) ----
    nCopy++;
    r_dst[ri]=dst; r_src[ri]=src; r_sz[ri]=sz; r_ret[ri]=roff; r_val[ri]=val; r_tid[ri]=this.threadId;
    ri=(ri+1)&(RING-1); if(rc<RING) rc++;
  }});
  setInterval(function(){ send({t:'mon', nCopy:nCopy, nRd:nRd, ringN:rc}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
