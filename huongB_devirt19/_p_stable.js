/* _p_stable.js v2 — is P's address stable within one process? */
'use strict';
const SO='libmetasec_ov.so'; const DRV=0x9fd98; const MAX=40;
let base=null; let n=0; let nCall=0; const seenAddr={}; const lenHist={};
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
function off(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():null; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base;
  Interceptor.attach(base.add(DRV),{
    onEnter(){
      nCall++;
      let len=-1; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){}
      const lk=(len>=0&&len<=256)?len:'big'; lenHist[lk]=(lenHist[lk]||0)+1;
      if(n>=MAX) return;
      if(len!==16) return;
      const p=this.context.x0; let val=null;
      try{ val=hx(p.readByteArray(16)); }catch(e){ return; }
      if(!val || val==='00000000000000000000000000000000') return;
      n++;
      const addr=p.toString();
      seenAddr[addr]=(seenAddr[addr]||0)+1;
      send({t:'HIT',i:n,addr:addr,val:val,caller:off(this.context.lr)});
    }
  });
  send({t:'info',msg:'installed drv@0x9fd98 base='+base});
  return true;
}
const boot=()=>{ if(!install()) setTimeout(boot,150); };
boot();
setInterval(()=>{ send({t:'mon',hits:n,drvCalls:nCall,uniqAddr:Object.keys(seenAddr).length,lenHist:lenHist,addrs:seenAddr}); },4000);
