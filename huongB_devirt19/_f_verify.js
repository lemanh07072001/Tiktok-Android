// _f_verify.js — RIGOROUSLY verify whether F(0x191f40) produces slot16. Hook interp 0x52924 gated
// x0=base+0x191f40; on entry record x4 (output std::string obj); on leave read x4's data (data_ptr for
// >15B, else inline) = F's OUTPUT. Learn slot16 pool via SM3. Report F-output + whether it matches a
// real slot16. Lesson from prior error: verify the ACTUAL output bytes, not the unchanging regfile.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F_PROG=0x191f40, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
const pool={}; let nF=0, nrep=0;
function readStr(objPtr){ // std::string: [data_ptr(8)][size(8)][cap/inline(16)] ; SSO if size<=15
  try{ const size=objPtr.add(8).readU64().valueOf ? objPtr.add(8).readU64() : 0;
    const sz=Number(objPtr.add(8).readU64());
    let dataP;
    if(sz>15){ dataP=objPtr.readPointer(); } else { dataP=objPtr; /* SSO inline at obj? actually inline at obj+0? */ }
    // try both: heap data_ptr and inline
    const heap=hx(objPtr.readPointer(),32);
    const inline=hx(objPtr,32);
    return {size:sz, heap:heap, inline:inline};
  }catch(e){ return {err:''+e}; }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    let x0=a[0]; try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==F_PROG) return; }catch(e){ return; }
    nF++; this.isF=true; this.x4=a[4]; this.inX4=readStr(a[4]);
  }, onLeave(){
    if(!this.isF||nrep>=8) return; nrep++;
    const out=readStr(this.x4);
    // check if any 16B window of out.heap or out.inline is a pool slot16
    let hit=null;
    const hay=(out.heap||'')+(out.inline||'');
    for(const s in pool){ if(hay.indexOf(s)>=0){ hit=s; break; } }
    send({t:'fout', nF:nF, x4:this.x4.toString(), out:out, in_x4:this.inX4, poolHit:hit, poolsz:Object.keys(pool).length});
  }});
  send({t:'info',msg:'f-verify installed (F 0x191f40)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
