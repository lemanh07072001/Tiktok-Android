/* _p_source.js — find the SOURCE of slot16.
 * Hypothesis: producer copies slot16 into fresh P from a stable session field.
 * Hook memcpy/memmove: record dst->{src,n,val,csite} for n in {16,32,64} & caller in libmetasec.
 * Hook SM3-driver 0x9fd98: on len==16 nonzero P, look up dst==P in recent-copy map.
 *   MATCH -> emit src (origin). Also keep a val-index fallback.
 * If NO matches across many hits -> producer writes P via inline stores (not memcpy).
 */
'use strict';
const SO='libmetasec_ov.so'; const DRV=0x9fd98; const MAX=60;
let base=null,lo=null,hi=null; let n=0, nMatch=0, nInline=0;
const byDst={}; const byVal={}; const order=[]; const CAP=1024;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(p,len){ try{ const u=new Uint8Array(p.readByteArray(len)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
function off(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():null; }
function rangeOf(p){ try{ const r=Process.findRangeByAddress(p); if(r) return (r.protection)+' '+(r.file?r.file.path:'anon')+' sz=0x'+r.size.toString(16);}catch(e){} return '?'; }
function rec(dst,src,nn,csite){
  const val=hx(dst,16); if(!val) return;
  const k=dst.toString();
  byDst[k]={src:src.toString(),n:nn,val:val,csite:csite};
  byVal[val]={src:src.toString(),n:nn,csite:csite,dst:k};
  order.push(k); if(order.length>CAP){ const old=order.shift(); const v=byDst[old]; if(v) delete byVal[v.val]; delete byDst[old]; }
}
function hookCopy(name){
  const a=Module.findGlobalExportByName(name); if(!a) return;
  Interceptor.attach(a,{
    onEnter(args){ this.dst=args[0]; this.src=args[1]; let nn=-1; try{ nn=parseInt(args[2].toString()); }catch(e){} this.n=nn; this.cs=this.returnAddress; },
    onLeave(){ if(this.n!==16 && this.n!==32 && this.n!==64) return; if(!inSelf(this.cs)) return; rec(this.dst,this.src,this.n,off(this.cs)); }
  });
  send({t:'info',msg:'hooked '+name});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  hookCopy('memcpy'); hookCopy('memmove');
  Interceptor.attach(base.add(DRV),{
    onEnter(){
      if(n>=MAX) return;
      let len=-1; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){}
      if(len!==16) return;
      const p=this.context.x0; const val=hx(p,16);
      if(!val || val==='00000000000000000000000000000000') return;
      n++;
      const k=p.toString();
      let m1=byDst[k]||null; let via='dst';
      if(!m1 && byVal[val]){ m1=byVal[val]; via='val'; }
      if(m1){ nMatch++; send({t:'MATCH',i:n,via:via,slot16:val,src:m1.src,srcRange:rangeOf(ptr(m1.src)),n:m1.n,csite:m1.csite,P:k}); }
      else { nInline++; send({t:'NOCOPY',i:n,slot16:val,P:k,Prange:rangeOf(p)}); }
    }
  });
  send({t:'info',msg:'installed base='+base});
  return true;
}
const boot=()=>{ if(!install()) setTimeout(boot,150); };
boot();
setInterval(()=>{ send({t:'mon',hits:n,match:nMatch,nocopy:nInline,mapSz:order.length}); },4000);
