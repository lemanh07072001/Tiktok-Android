/* _p_caller_probe.js — advance ONE real frame above the SM3 consumer.
 * Hook the generic closure-invoker @0xa1004. Filter obj[0]==&SM3driver(0x9fdac)&&obj[0x10]==16.
 * Capture this.returnAddress (the invoker's caller = task-driver), obj layout, *P.
 */
'use strict';
const SO='libmetasec_ov.so', INVOKER=0xa1004, SM3_DRV=0x9fd98, MAXTRIG=10;
let base=null,lo=null,hi=null,nT=0;
function o(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return '+0x'+p.sub(base).toString(16);}catch(e){} 
  try{const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():null; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info',msg:'base='+base});
  Interceptor.attach(base.add(INVOKER),{
    onEnter(args){
      if(nT>=MAXTRIG) return;
      const ctx=this.context, obj=ctx.x0;
      let fn=null,P=null,w1=-1,x2=null;
      try{ fn=obj.readPointer(); P=obj.add(8).readPointer(); w1=obj.add(0x10).readU32(); x2=obj.add(0x18).readPointer(); }catch(e){ return; }
      // filter: fnptr == SM3 driver, length==16
      let fnoff=-1; try{ if(fn.compare(lo)>=0&&fn.compare(hi)<0) fnoff=fn.sub(base).toInt32(); }catch(e){}
      if(fnoff!==SM3_DRV) return;
      if(w1!==16) return;
      let sl=null; try{ const b=new Uint8Array(P.readByteArray(16)); let z=true,s=''; for(let i=0;i<16;i++){ if(b[i])z=false; s+=('0'+b[i].toString(16)).slice(-2);} if(z) return; sl=s; }catch(e){ return; }
      nT++;
      // dump obj header + caller
      let objhdr=[]; try{ for(let k=0;k<0x30;k+=8) objhdr.push(obj.add(k).readPointer().toString()); }catch(e){}
      send({t:'HIT',n:nT,slot16:sl,P:P.toString(),caller:o(this.returnAddress),x2:o(x2),obj:obj.toString(),objhdr:objhdr});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>send({t:'mon',trig:nT}),4000);
