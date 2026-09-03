'use strict';
const SO='libmetasec_ov.so'; const SM3_DRV=0x9fdac;
let base=null,lo=null,hi=null;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }
function hexB(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }
// scan [start,start+len) for needle bytes; return array of offsets
function scanFor(start,len,needle){
  const res=[];
  try{
    const ab=start.readByteArray(len); if(!ab) return res;
    const u=new Uint8Array(ab); const n=needle.length;
    for(let i=0;i+n<=u.length;i++){
      let ok=true;
      for(let j=0;j<n;j++){ if(u[i+j]!==needle[j]){ ok=false; break; } }
      if(ok) res.push(i);
    }
  }catch(e){}
  return res;
}
let got=0; const MAX=6; const seen={};
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(SM3_DRV),{
    onEnter(a){
      const c=this.context;
      let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const B=c.x0; const V=hexB(B,16);
      if(!V || V==='00000000000000000000000000000000') return;
      if(seen[V]) { seen[V]++; return; }         // only first occurrence of each value
      seen[V]=1;
      if(got>=MAX) return; got++;
      const needle=[]; for(let i=0;i<16;i+=2){ needle.push(parseInt(V.substr(i,2),16)); needle.push(parseInt(V.substr(i+2,2),16)); }
      const nb=[]; for(let i=0;i<16;i++) nb.push(parseInt(V.substr(i*2,2),16));
      // scan context page around x19 and the 0x754561xxxx region derived from x19
      const x19=c.x19, x21=c.x21, x23=c.x23;
      const results={};
      function reg(name,center,back,fwd){
        try{
          const st=center.sub(back);
          const offs=scanFor(st, back+fwd, nb);
          if(offs.length) results[name]=offs.map(o=>o-back); // signed offset from center
        }catch(e){}
      }
      reg('x19', x19, 0x400, 0x4000);
      reg('x21', x21, 0x400, 0x2000);
      reg('x23', x23, 0x400, 0x2000);
      send({t:'HIT', v:V, buf:B.toString(),
            x19:x19.toString(), x21:x21.toString(), x23:x23.toString(),
            src:results});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,150); }; setTimeout(t,200); }
setInterval(function(){ send({t:'mon', got:got, distinct:Object.keys(seen).length}); }, 5000);
