// _f_diff.js — find 0x191f40's OUTPUT by diffing its x1 input-graph buffers before/after execution.
// Hook interp 0x52924 gated x0=0x191f40. onEnter: snapshot q0..q7 (x1[i] deref, 64B each). onLeave:
// snapshot again; the buffer that CHANGED = F's output. Learn slot16 pool (SM3). Report changed buffers
// + whether any 16B window = a real slot16 (verify F IS the producer). Also capture full regfile x24.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F_PROG=0x191f40, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function snap(x1){ const s=[]; for(let i=0;i<8;i++){ try{ const q=ptr(x1).add(i*8).readPointer(); s.push({i:i, ptr:q.toString(), data:hx(q,64)}); }catch(e){ s.push({i:i}); } } return s; }
const pool={}; let n=0;
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
    this.isF=true; this.x1=a[1]; this.x24=this.context.x24; this.pre=snap(a[1]); this.rfPre=hx(this.context.x24,256);
  }, onLeave(){
    if(!this.isF||n>=10) return; n++;
    const post=snap(this.x1); const rfPost=hx(this.x24,256);
    const changed=[];
    for(let i=0;i<8;i++){ if(this.pre[i]&&post[i]&&this.pre[i].data&&post[i].data&&this.pre[i].data!==post[i].data){
      changed.push({i:i, ptr:post[i].ptr, before:this.pre[i].data, after:post[i].data}); } }
    // check pool membership in changed buffers + regfile
    const hay=changed.map(c=>c.after).join('')+(rfPost||'');
    let hit=null; for(const s in pool){ if(hay.indexOf(s)>=0){ hit=s; break; } }
    send({t:'fdiff', n:n, nchanged:changed.length, changed:changed, rfChanged:(this.rfPre!==rfPost), poolHit:hit, poolsz:Object.keys(pool).length});
  }});
  setTimeout(function(){ send({t:'poollate', pool:Object.keys(pool)}); }, 30000);
  send({t:'info',msg:'f-diff installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
