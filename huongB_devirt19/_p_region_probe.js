/* _p_region_probe.js — WHERE does P live + WHO calls the consumer?
 * At each nonzero-slot16 SM3-driver hit:
 *   - Process.findRangeByAddress(P) -> mapping {base,size,prot,file}
 *   - Thread.backtrace(ctx) -> frames mapped to module+offset (libmetasec highlighted)
 * No allocator hooks. No WP. No re-register. Pure observation.
 */
'use strict';
const SO='libmetasec_ov.so', SM3_DRV=0x9fdac, MAXTRIG=8;
let base=null,lo=null,hi=null; let nTrig=0;
function fr(p){ try{ const r=Process.findRangeByAddress(p); if(!r) return null;
  return {b:r.base.toString(),sz:r.size,prot:r.protection,file:r.file?r.file.path+'@'+r.file.offset:null}; }catch(e){return null;} }
function bt(ctx){
  let out=[];
  try{
    const frames=Thread.backtrace(ctx,Backtracer.ACCURATE);
    for(let i=0;i<frames.length && i<16;i++){
      const f=frames[i]; let m=null;
      try{ m=Process.findModuleByAddress(f); }catch(e){}
      if(m){ out.push(m.name+'+0x'+f.sub(m.base).toString(16)); }
      else out.push(f.toString());
    }
  }catch(e){ out.push('bt-err:'+e); }
  return out;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'base='+base});
  Interceptor.attach(base.add(SM3_DRV),{
    onEnter(args){
      if(nTrig>=MAXTRIG) return;
      const ctx=this.context;
      let w1=-1; try{ w1=parseInt(ctx.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const x0=ctx.x0; let b=null; try{ b=new Uint8Array(x0.readByteArray(16)); }catch(e){ return; }
      let z=true; for(let i=0;i<16;i++) if(b[i]!==0){z=false;break;} if(z) return;
      let s=''; for(let i=0;i<16;i++) s+=('0'+b[i].toString(16)).slice(-2);
      nTrig++;
      send({t:'HIT',n:nTrig,slot16:s,P:x0.toString(),region:fr(x0),bt:bt(ctx)});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>send({t:'mon',trig:nTrig}),4000);
