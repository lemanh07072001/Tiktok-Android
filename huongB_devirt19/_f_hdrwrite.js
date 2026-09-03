// Locate header (scan slot16), then detect which VM invocation (0x52924) WRITES a new slot16 into it.
// before/after diff at call granularity -> no HW-watchpoint needed. Report program-id(x0)+native LR.
'use strict';
const SO='libmetasec_ov.so', VM=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function scanAll(hexpat){ const ps=hexpat.match(/../g).join(' '); const hits=[];
  for(const r of Process.enumerateRanges('rw-')){ if(r.size>64*1024*1024) continue;
    try{ const fs=Memory.scanSync(r.base,r.size,ps); for(const f of fs) hits.push(f.address); }catch(e){}
    if(hits.length>=30) break; } return hits; }
let hdrBase=null, hdrLen=0x60, base=null, lo=null, hi=null; const hits=[]; let armed=false;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); const chain={};
  // VM watch: compare header before/after each invocation
  Interceptor.attach(base.add(VM),{
    onEnter(a){ if(!armed) return; let x0=a[0];
      try{ if(x0.compare(lo)<0||x0.compare(hi)>=0){ this.w=false; return; } }catch(e){ this.w=false; return; }
      this.w=true; this.prog='0x'+x0.sub(base).toString(16); this.lr=this.context.lr;
      this.before=hx(hdrBase,hdrLen);
    },
    onLeave(){ if(!this.w||!armed) return;
      const after=hx(hdrBase,hdrLen);
      if(after && after!==this.before){
        let lrs; try{ lrs = this.lr.compare(lo)>=0&&this.lr.compare(hi)<0 ? '0x'+this.lr.sub(base).toString(16) : this.lr.toString(); }catch(e){ lrs=''+this.lr; }
        send({t:'write', prog:this.prog, lr:lrs, before:this.before, after:after});
      }
    }
  });
  Interceptor.attach(base.add(SM3),{onEnter(){
    if(armed) return;
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],Ln=a.length; if(Ln<9) return;
    let bl=0; for(let i=Ln-8;i<Ln;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<Ln)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot==='00'.repeat(16)||pr>=12){ delete chain[tid]; return; }
    // find the HEADER hit: anon rw- containing "K-VERSION"(4b2d56455253494f4e) within 0x40 after slot
    const founds=scanAll(slot);
    for(const h of founds){
      const ctx=hx(h.sub(0x30),0x80);
      if(ctx && ctx.indexOf('4b2d56455253494f4e')>=0){   // "K-VERSION" nearby => header
        // header struct base ~ start of this entry: back up to the 020102 marker
        hdrBase=h.sub(0x30); hdrLen=0x80; armed=true;
        send({t:'hdrloc', slot16:slot, hdrBase:hdrBase.toString(), ctx:ctx});
        break;
      }
    }
    delete chain[tid];
  }});
  send({t:'info',msg:'hdrwrite installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
