// _vm_ctxtrace.js — COMBINED capture (same invocation, same ASLR): F's instruction TRACE + deep MEMORY
// (context from getter) + the slot16 F produces. Feed all to compute_slot16.py → replay ONE invocation
// end-to-end (no seed substitution) → validate got==produced slot16. Proves capture+interpreter pipeline.
'use strict';
const SO='libmetasec_ov.so', VM_ENTRY=0x52924, DISPATCH=0x55950, GETTER=0x13b04c, SM3=0xa0748;
const F_PROG=parseInt((typeof MSPROG!=='undefined'&&MSPROG)||'0x191f40');
const CAP=parseInt((typeof PGCAP!=='undefined'&&PGCAP)||'4000',10);
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size), modBase=base;
  const PGMASK=ptr('0xfffffffffffff000'); const seen={}, mem={};
  function grabPage(pv){try{const pg=ptr(pv).and(PGMASK);const k=pg.toString();if(seen[k])return null;seen[k]=1;const ab=pg.readByteArray(0x1000);if(!ab)return null;mem[k]=hx(ab);return new Uint8Array(ab);}catch(e){return null;}}
  function scanPtrs(u8,out){for(let o=0;o+8<=u8.length;o+=8){const b4=u8[o+4];if((b4>=0x72&&b4<=0x7f)&&u8[o+5]===0&&u8[o+6]===0&&u8[o+7]===0){let v=0;for(let i=3;i>=0;i--)v=v*256+u8[o+i];out.push(ptr('0x'+b4.toString(16)+('00000000'+v.toString(16)).slice(-8)));}}}
  function bfs(seeds){let f=seeds.slice();for(let lvl=0;lvl<8&&Object.keys(seen).length<CAP;lvl++){const nx=[];for(let k=0;k<f.length&&Object.keys(seen).length<CAP;k++){const u8=grabPage(f[k]);if(u8)scanPtrs(u8,nx);}f=nx;if(!f.length)break;}}
  let captured=false, capturedTid=0, tracing=false, ctxDone=false, sentAll=false;
  let entryRegfile=null, entryRegs=null, entryX24=null, entryStack=null, entryStackBase=null, ctxSaved=null;
  const trace=[]; const slotpool={}; const chainSM={};
  function sendAll(ctxptr, slot16){
    if(sentAll)return; sentAll=true;
    send({t:'region',name:'regfile',vaddr:entryX24?entryX24.toString():'0',hex:entryRegfile});
    if(entryStack)send({t:'region',name:'stack',vaddr:entryStackBase,hex:entryStack});
    const keys=Object.keys(mem);
    for(let s=0;s<keys.length;s+=50){const ch={};for(let j=s;j<Math.min(s+50,keys.length);j++)ch[keys[j]]=mem[keys[j]];send({t:'memchunk',mem:ch});}
    for(let s=0;s<trace.length;s+=800){send({t:'trace',from:s,rows:trace.slice(s,s+800)});}
    send({t:'entry',base:base.toString(),tid:capturedTid,nmem:keys.length,regs:entryRegs,ctxptr:ctxptr?ctxptr.toString():null,ntrace:trace.length,slot16:slot16||null});
    send({t:'done'});
  }
  // #19 SM3 → collect slot16 pool (validate target)
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{st=hx(this.context.x0.add(8).readByteArray(32));inp=new Uint8Array(this.context.x1.readByteArray(64));}catch(e){return;}
    if(st===IV)chainSM[tid]=Array.from(inp);else if(chainSM[tid]){for(let i=0;i<64;i++)chainSM[tid].push(inp[i]);}else return;
    const a=chainSM[tid],L=a.length;if(L<9)return;let bl=0;for(let i=L-8;i<L;i++)bl=bl*256+a[i];const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80)return;if(a[mlen-1]!==0x30||mlen<40){delete chainSM[tid];return;}
    let slot='',pr=0;for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2);if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12)slotpool[slot]=1;delete chainSM[tid];
  }});
  // dispatch: while tracing this tid, collect [off, word, op]
  Interceptor.attach(base.add(DISPATCH),{onEnter(){
    if(!tracing||this.threadId!==capturedTid)return;
    try{const bcp=this.context.x23.readPointer();const off=bcp.sub(modBase).toInt32()>>>0;const w=bcp.add(4).readU32()>>>0;
      trace.push({op:w&0x3f,word:'0x'+w.toString(16),off:off});}catch(e){}
    if(trace.length>=6000){tracing=false;}
  }});
  // getter: ctxptr live → deep BFS + finish (send). Also stop tracing.
  Interceptor.attach(base.add(GETTER),{onEnter(){
    if(!captured||this.threadId!==capturedTid||ctxDone)return;
    let ctxptr=null;try{ctxptr=this.context.x20.add(0x10).readPointer();}catch(e){}
    if(!ctxptr)return; ctxDone=true;
    const seeds=[ctxptr];try{for(let i=0;i<32;i++)seeds.push(ptr(entryX24).add(i*8).readPointer());}catch(e){}
    ['x0','x1','x2','x19','x20','x21','x22'].forEach(r=>{try{seeds.push(this.context[r]);}catch(e){}});
    bfs(seeds);   // capture context; KEEP tracing (F continues after the call-out)
    ctxSaved=ctxptr;
    send({t:'ctx',ctxptr:ctxptr.toString(),npg:Object.keys(seen).length,ntrace:trace.length,slot16:Object.keys(slotpool)[0]||null});
  }});
  // F entry: capture regfile + start tracing + F-entry BFS
  Interceptor.attach(base.add(VM_ENTRY),{onEnter(a){
    if(captured)return; if(!this.context.x0.equals(base.add(F_PROG)))return;
    captured=true; capturedTid=this.threadId; tracing=true; this.isF=true;
    const c=this.context; entryX24=c.x24; entryRegfile=rd(c.x24,256);
    entryRegs={};['x0','x1','x2','x3','x4','x5','x6','x19','x20','x21','x22','x23','x24','x25','x26','fp','lr','sp','pc'].forEach(r=>{try{entryRegs[r]=c[r].toString();}catch(e){entryRegs[r]='?';}});
    const seeds=[];['x0','x1','x2','x3','x4','x5','x6','x19','x20','x21','x25','x26','sp'].forEach(r=>{try{seeds.push(c[r]);}catch(e){}});
    try{for(let i=0;i<32;i++)seeds.push(ptr(c.x24).add(i*8).readPointer());}catch(e){}
    bfs(seeds);
    entryStack=rd(c.sp.sub(0x800),0x4000)||rd(c.sp.sub(0x800),0x2000); entryStackBase=c.sp.sub(0x800).toString();
    send({t:'info',msg:'F-entry tid='+this.threadId+' regfile='+(entryRegfile?'ok':'NULL')+' tracing...'});
    setTimeout(function(){ tracing=false; sendAll(ctxSaved, Object.keys(slotpool)[0]||null); }, 12000);
  }, onLeave(){
    if(!this.isF||sentAll)return;
    tracing=false;
    send({t:'info',msg:'F onLeave — trace='+trace.length});
    sendAll(ctxSaved, Object.keys(slotpool)[0]||null);
  }});
  send({t:'info',msg:'ctxtrace installed F_PROG=0x'+F_PROG.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
