// _invoker_seq.js — Find the slot16 PRODUCER: it is (hypothesis) a native closure the VM invokes via the
// generic invoker 0x9b604 (`ldp x9,x8,[x0]; ldr x0,[x0,#0x10]; blr x9` => fn=*(desc), arg=*(desc+0x10)),
// dispatched BEFORE the SM3-driver hashes the produced slot16. We keep a ring buffer of recent invocations
// {seq,tid,fn,arg,argAfter32}. At the SM3-driver (x0=P holds slot16 V, w1=16) we dump the ring for that tid;
// the producer = the invocation whose argAfter (or retval-deref) contains V. This pins the producer fn cheaply
// without a full VM trace. onEnter reads fn/arg; onLeave re-reads arg buffer (fn may have written slot16 there)
// and retval. Gate safe after 12s. Bounded ring (global) to cap memory.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac, INV=0x9b604;
let base=null, lo=null, hi=null, safe=false, seq=0, drvHits=0; const MAXDRV=6;
const RING=[]; const RINGMAX=4000;           // global ring of recent invoker calls
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function cls(p){ try{ if(p.isNull()) return 'null'; }catch(e){ return 'bad'; }
  const s=selfOff(p); if(s) return s;
  try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16); }catch(e){}
  return p.toString(); }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function push(rec){ RING.push(rec); if(RING.length>RINGMAX) RING.shift(); }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  // ---- generic closure invoker ----
  Interceptor.attach(base.add(INV), {
    onEnter(a){ if(!safe){ this.skip=true; return; } const c=this.context; const desc=c.x0;
      let fn=null, arg=null; try{ fn=desc.readPointer(); }catch(e){}
      try{ arg=desc.add(0x10).readPointer(); }catch(e){}
      this.tid=this.threadId; this.seq=++seq; this.fn=fn; this.arg=arg; this.fnCls=fn?cls(fn):null;
      this.argBefore=arg?peek(arg,32):null;
    },
    onLeave(ret){ if(this.skip) return; const argAfter=this.arg?peek(this.arg,32):null;
      let rd=null; try{ if(ret && !ret.isNull()) rd=peek(ret,32); }catch(e){}
      // only bother ringing invocations that target a libmetasec fn (producer is in-lib) to cut noise
      if(this.fn && inSelf(this.fn)){
        push({seq:this.seq, tid:this.tid, fn:this.fnCls, arg:this.arg?this.arg.toString():null,
              before:this.argBefore, after:argAfter, ret:ret?ret.toString():null, retd:rd});
      }
    }
  });
  // ---- SM3 driver: trigger = slot16 consumption ----
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||drvHits>=MAXDRV) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; drvHits++;
    const tid=this.threadId;
    // search ring (this tid) for a prior call whose captured bytes contain V
    const hits=[]; for(let i=RING.length-1;i>=0 && hits.length<6;i--){ const r=RING[i]; if(r.tid!==tid) continue;
      const inAfter=r.after && r.after.indexOf(V)>=0; const inRet=r.retd && r.retd.indexOf(V)>=0;
      const inBefore=r.before && r.before.indexOf(V)>=0;
      if(inAfter||inRet||(inBefore&&!inAfter)) hits.push({seq:r.seq, fn:r.fn, where:(inAfter?'after':'')+(inRet?'/ret':'')+(inBefore?'/before':''), arg:r.arg, after:r.after, ret:r.ret, retd:r.retd});
    }
    // also emit the last 24 invoker fns (sequence context) for this tid
    const recent=[]; for(let i=RING.length-1;i>=0 && recent.length<24;i--){ if(RING[i].tid===tid) recent.push([RING[i].seq, RING[i].fn]); }
    send({t:'DRV', drv:drvHits, tid:tid, V:V, P:c.x0.toString(), producerHits:hits, recentFns:recent, ringLen:RING.length});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 12000);
setInterval(function(){
  // tally distinct invoker fns seen (frequency sanity)
  const freq={}; for(let i=0;i<RING.length;i++){ const f=RING[i].fn; freq[f]=(freq[f]||0)+1; }
  const top=Object.keys(freq).map(function(k){return [k,freq[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
  send({t:'mon', safe:safe, seq:seq, ringLen:RING.length, drvHits:drvHits, top:top});
}, 3000);
