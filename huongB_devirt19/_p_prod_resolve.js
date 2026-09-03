/* _p_prod_resolve.js — single-shot resolve of the obfuscated call blr@0xa02a8.
 * Per memory note, its return addr 0xa02ac == the "producer PRF" call site.
 * Capture: resolved target x8 (offset), args x0(=x21),x1(=x23), *x0/*x1 bytes.
 * Low-frequency (SM3-area), capped at N captures.
 */
'use strict';
const SO='libmetasec_ov.so', CALL=0xa02a8;
let base=null,lo=null,hi=null,n=0; const MAX=8;
function ioff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return '+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():null; }
function rd(p,k){ try{ const b=p.readByteArray(k); const u=new Uint8Array(b); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info',msg:'base='+base});
  Interceptor.attach(base.add(CALL),{
    onEnter(){ if(n>=MAX) return; n++;
      const c=this.context;
      let tgt=null,x0=null,x1=null,d0=null,d1=null,rng0=null,rng1=null;
      try{ tgt=ioff(c.x8); }catch(e){}
      try{ x0=c.x0.toString(); d0=rd(c.x0,32);
           const r=Process.findRangeByAddress(c.x0); rng0=r?(r.protection+' '+(r.file?r.file.path:'anon')+' sz=0x'+r.size.toString(16)):null; }catch(e){}
      try{ x1=c.x1.toString(); d1=rd(c.x1,32);
           const r=Process.findRangeByAddress(c.x1); rng1=r?(r.protection+' '+(r.file?r.file.path:'anon')+' sz=0x'+r.size.toString(16)):null; }catch(e){}
      send({t:'HIT',i:n,tgt:tgt,x0:x0,x1:x1,d0:d0,d1:d1,rng0:rng0,rng1:rng1});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150);}; setTimeout(f,300); }
setInterval(()=>send({t:'mon',n:n}),3000);
