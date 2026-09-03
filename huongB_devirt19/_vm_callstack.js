// _vm_callstack.js — reconstruct the VM program CALL HIERARCHY (nested 0x52924 interp calls).
// Per-thread stack of program ids (push x0 on interp-enter, pop on leave). When a crypto-cluster
// program runs, log its PARENT chain => the ORCHESTRATOR that wraps the crypto and writes the digest
// to the header. That orchestrator is the program to capture + unicorn-replay for slot16.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924;
const CRYPTO={0x186600:1,0x186420:1,0x186480:1,0x17f940:1,0x1864f0:1};
const stacks={}; const edges={}; const roots={}; let logged=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    const tid=this.threadId; let off;
    try{ const x0=a[0]; if(x0.compare(lo)<0||x0.compare(hi)>=0){ this.skip=1; return; } off=x0.sub(base).toInt32(); }catch(e){ this.skip=1; return; }
    this.off=off;
    if(!stacks[tid]) stacks[tid]=[];
    const st=stacks[tid];
    const parent = st.length? st[st.length-1] : null;
    st.push(off);
    // record call edge parent->child
    const pk='0x'+(parent!==null?parent.toString(16):'root');
    const ck='0x'+off.toString(16);
    const ek=pk+'->'+ck; edges[ek]=(edges[ek]||0)+1;
    if(parent===null) roots[ck]=(roots[ck]||0)+1;
    // when a crypto program runs, log its full parent chain (once per distinct chain)
    if(CRYPTO[off] && logged<40){
      const chain=st.map(x=>'0x'+x.toString(16)).join('>');
      if(!edges['__chain_'+chain]){ edges['__chain_'+chain]=1; logged++;
        send({t:'chain', crypto:ck, chain:chain, depth:st.length});
      }
    }
  }, onLeave(){
    if(this.skip) return; const tid=this.threadId; const st=stacks[tid]; if(st&&st.length) st.pop();
  }});
  setTimeout(function(){
    // dump top call edges + roots
    const es=Object.keys(edges).filter(k=>!k.startsWith('__chain_')).map(k=>[k,edges[k]]).sort((a,b)=>b[1]-a[1]);
    send({t:'edges', top:es.slice(0,50), roots:roots});
  }, 20000);
  send({t:'info',msg:'vm-callstack installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
