const MSPROG='0x1814f0';
// _vm_ctxcap.js — capture F-entry regfile + the DEVICE-CONTEXT object graph.
// KEY fix vs _vm_singleshot.js: the context F pointer-chases through is POPULATED DURING F by the
// libart call-outs (getter 0x13b04c returns the ctxptr). At F-ENTRY the ctxptr is null, so an entry-only
// BFS misses it. Here we (1) grab the F-entry regfile @x24, then (2) when the getter fires on the same
// tid (ctxptr now live), do a DEEP BFS from ctxptr + all regfile pointers to capture the populated
// context object graph. Combine → feed compute_slot16.py.
'use strict';
const SO='libmetasec_ov.so', VM_ENTRY=0x52924, GETTER=0x13b04c;
const F_PROG=parseInt((typeof MSPROG!=='undefined'&&MSPROG)||'0x191f40');
const CAP=parseInt((typeof PGCAP!=='undefined'&&PGCAP)||'4000',10);
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  const PGMASK=ptr('0xfffffffffffff000');
  const seen={}; const mem={};
  function grabPage(pv){
    try{ const pg=ptr(pv).and(PGMASK); const key=pg.toString();
      if(seen[key]) return null; seen[key]=1;
      const ab=pg.readByteArray(0x1000); if(!ab) return null;
      mem[key]=hx(ab); return new Uint8Array(ab);
    }catch(e){ return null; }
  }
  function scanPtrs(u8, out){
    for(let o=0;o+8<=u8.length;o+=8){
      const b4=u8[o+4];
      if((b4>=0x72&&b4<=0x7f)&&u8[o+5]===0&&u8[o+6]===0&&u8[o+7]===0){
        let v=0; for(let i=3;i>=0;i--) v=v*256+u8[o+i]; // low 4 bytes
        out.push(ptr('0x'+b4.toString(16)+('00000000'+v.toString(16)).slice(-8)));
      }
    }
  }
  function bfs(seeds){
    let frontier=seeds.slice();
    for(let lvl=0; lvl<8 && Object.keys(seen).length<CAP; lvl++){
      const next=[];
      for(let k=0;k<frontier.length && Object.keys(seen).length<CAP;k++){
        const u8=grabPage(frontier[k]); if(u8) scanPtrs(u8,next);
      }
      frontier=next; if(!frontier.length) break;
    }
  }
  let captured=false, capturedTid=0, fhits=0, entryRegfile=null, entryRegs=null, entryX24=null, ctxDone=false;
  let entryStack=null, entryStackBase=null, sentAll=false;
  function sendAll(ctxptr){
    if(sentAll) return; sentAll=true;
    send({t:'region',name:'regfile',vaddr:entryX24?entryX24.toString():'0',hex:entryRegfile});
    if(entryStack) send({t:'region',name:'stack',vaddr:entryStackBase,hex:entryStack});
    const keys=Object.keys(mem);
    for(let s=0;s<keys.length;s+=50){const ch={};for(let j=s;j<Math.min(s+50,keys.length);j++)ch[keys[j]]=mem[keys[j]];send({t:'memchunk',mem:ch});}
    send({t:'entry',base:base.toString(),tid:capturedTid,nmem:keys.length,regs:entryRegs,ctxptr:ctxptr?ctxptr.toString():null,ctxDone:ctxDone});
    send({t:'done'});
  }
  // getter: fires during F; ctxptr live at [x20+0x10]. On the captured tid, deep-BFS the context graph + SEND.
  // (send here, NOT onLeave — the orchestrator is a giant VM whose onLeave never fires.)
  Interceptor.attach(base.add(GETTER),{onEnter(){
    if(!captured || this.threadId!==capturedTid || ctxDone) return;
    let ctxptr=null; try{ ctxptr=this.context.x20.add(0x10).readPointer(); }catch(e){}
    if(!ctxptr) return;
    ctxDone=true;
    const seeds=[ctxptr];
    try{ for(let i=0;i<32;i++) seeds.push(ptr(entryX24).add(i*8).readPointer()); }catch(e){}
    ['x0','x1','x2','x19','x20','x21','x22'].forEach(r=>{try{seeds.push(this.context[r]);}catch(e){}});
    bfs(seeds);
    send({t:'ctx', ctxptr:ctxptr.toString(), npg:Object.keys(seen).length});
    sendAll(ctxptr);   // send everything now (context is live; don't wait for onLeave)
  }});
  Interceptor.attach(base.add(VM_ENTRY),{onEnter(a){
    if(captured) return;
    if(!this.context.x0.equals(base.add(F_PROG))) return;
    fhits++;
    captured=true; capturedTid=this.threadId;
    const c=this.context; entryX24=c.x24;
    entryRegfile=rd(c.x24,256);
    entryRegs={}; ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp','pc'].forEach(r=>{try{entryRegs[r]=c[r].toString();}catch(e){entryRegs[r]='?';}});
    // F-entry BFS (shallow, the context comes from the getter later)
    const seeds=[];
    ['x0','x1','x2','x3','x4','x5','x6','x19','x20','x21','x25','x26','sp'].forEach(r=>{try{seeds.push(c[r]);}catch(e){}});
    try{ for(let i=0;i<32;i++) seeds.push(ptr(c.x24).add(i*8).readPointer()); }catch(e){}
    bfs(seeds);
    // stack (module-level; getter/timeout will send)
    entryStack=rd(c.sp.sub(0x800),0x4000)||rd(c.sp.sub(0x800),0x2000);
    entryStackBase=c.sp.sub(0x800).toString();
    send({t:'info',msg:'F-entry captured tid='+this.threadId+' x24='+c.x24+' regfile='+(entryRegfile?'ok':'NULL')});
    // fallback: if the getter never fires within 8s, send what we have (F-entry-only)
    setTimeout(function(){ sendAll(null); }, 8000);
  }});
  send({t:'info',msg:'ctxcap installed F_PROG=0x'+F_PROG.toString(16)+' CAP='+CAP});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
