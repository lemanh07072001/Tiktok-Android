/* _p_vmcallout.js — enumerate the VM's native vocabulary.
 * Hook VM indirect callout @0x5594c (blr x8). Histogram of x8 target offset.
 * For each DISTINCT target, record first-seen args x0..x3 (best-effort).
 */
'use strict';
const SO='libmetasec_ov.so', CALLOUT=0x5594c;
let base=null,lo=null,hi=null; const hist={}; const firstargs={}; let n=0;
function ioff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return p.sub(base).toInt32(); }catch(e){} return -1; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info',msg:'base='+base});
  Interceptor.attach(base.add(CALLOUT),{
    onEnter(){ n++;
      const ctx=this.context; let tgt=-1;
      try{ tgt=ioff(ctx.x8); }catch(e){}
      const key=tgt;
      hist[key]=(hist[key]||0)+1;
      if(!(key in firstargs)){
        try{ firstargs[key]={x0:ctx.x0.toString(),x1:ctx.x1.toString(),x2:ctx.x2.toString(),x3:ctx.x3.toString()}; }catch(e){ firstargs[key]={}; }
      }
    }
  });
  send({t:'info',msg:'callout hook ok'}); send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>{
  const top=Object.keys(hist).map(k=>[k,hist[k]]).sort((a,b)=>b[1]-a[1]);
  send({t:'mon',n:n,distinct:top.length,top:top.slice(0,20)});
},4000);
