/* _pool_probe.js — locate libmetasec's internal memory-pool creation.
 * Hook mmap/mprotect; keep only calls whose return address is inside libmetasec.
 * Record {size, prot, callsite-offset}. The big anon slabs (~0xfb000, 0x400000)
 * that hold SM3 scratch + the slot16 P-arena are carved here → find pool mgr.
 */
'use strict';
const SO='libmetasec_ov.so';
let base=null,lo=null,hi=null; const seen={}; let nAll=0,nSelf=0;
function within(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(within(p)) return '+0x'+p.sub(base).toString(16); }catch(e){} return null; }
function callerSelf(retaddr){ return off(retaddr); }
function hook(name){
  const a=Module.findGlobalExportByName(name); if(!a){ send({t:'info',msg:name+' not found'}); return; }
  try{
    Interceptor.attach(a,{
      onEnter(args){ this.sz=args[1]; this.prot=args[2]; },
      onLeave(ret){
        nAll++;
        const rc=this.returnAddress; const cs=callerSelf(rc);
        if(!cs) return; nSelf++;
        const sz=this.sz?this.sz.toInt32?this.sz.toInt32():parseInt(this.sz.toString()):0;
        const key=name+'@'+cs+':'+sz;
        if(!(key in seen)){ seen[key]=0; send({t:'POOL',fn:name,callsite:cs,size:'0x'+(sz>>>0).toString(16),ret:ret?ret.toString():null}); }
        seen[key]++;
      }
    });
    send({t:'info',msg:'hooked '+name});
  }catch(e){ send({t:'info',msg:'hook fail '+name+' '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info',msg:'base='+base+' size=0x'+m.size.toString(16)});
  ['mmap','mprotect'].forEach(hook);
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150);}; setTimeout(f,300); }
setInterval(()=>send({t:'mon',nAll:nAll,nSelf:nSelf,distinct:Object.keys(seen).length}),3000);
