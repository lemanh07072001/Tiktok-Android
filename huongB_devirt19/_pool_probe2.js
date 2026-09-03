/* _pool_probe2.js — hook mmap IMMEDIATELY at load (before libmetasec init).
 * Record every large anon mmap (size>=0x80000) with size+raw return addr.
 * Poll for libmetasec; when base known, resolve which mmaps' callers are inside it.
 */
'use strict';
const SO='libmetasec_ov.so'; const MIN=0x80000;
let base=null,lo=null,hi=null; const recs=[]; let nBig=0;
function resolveMod(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+ '+0x'+p.sub(m.base).toString(16); }catch(e){} return p?p.toString():null; }
// hook mmap right now (libc present from start)
const mmapPtr=Module.findGlobalExportByName('mmap');
if(mmapPtr){
  Interceptor.attach(mmapPtr,{
    onEnter(a){ this.len=a[1]; this.prot=a[2]; this.flags=a[3]; },
    onLeave(ret){
      let len=0; try{ len=parseInt(this.len.toString()); }catch(e){}
      if(len<MIN) return;
      nBig++;
      const rc=this.returnAddress;
      const rec={size:'0x'+(len>>>0).toString(16), ret:ret?ret.toString():null, caller:resolveMod(rc), rawcaller:rc?rc.toString():null};
      recs.push(rec);
      send({t:'MMAP',rec:rec});
    }
  });
  send({t:'info',msg:'mmap hooked at load'});
} else send({t:'info',msg:'mmap NOT found'});
// poll libmetasec, then re-annotate which recs are self
const poll=()=>{ const m=Process.findModuleByName(SO);
  if(m){ base=m.base; lo=base; hi=base.add(m.size);
    send({t:'info',msg:'libmetasec base='+base+' size=0x'+m.size.toString(16)});
    const self=recs.filter(r=>{ try{ return r.rawcaller && ptr(r.rawcaller).compare(lo)>=0 && ptr(r.rawcaller).compare(hi)<0; }catch(e){ return false; } });
    send({t:'SELFMMAPS', count:self.length, recs:self});
  } else setTimeout(poll,120);
};
poll();
setInterval(()=>{
  let self=[]; if(base){ self=recs.filter(r=>{ try{ return r.rawcaller && ptr(r.rawcaller).compare(lo)>=0 && ptr(r.rawcaller).compare(hi)<0; }catch(e){ return false; } }); }
  send({t:'mon',nBig:nBig,self:self.length,base:base?base.toString():null});
},3000);
