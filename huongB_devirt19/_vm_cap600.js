// _vm_cap600.js — capture I/O of the crypto VM programs (0x186600 outlier + cluster) to confirm
// which produces slot16. VM ABI (from F): x0=prog,x1=inbuf,x2=tableA,x3=tableB,x4=outbuf.
// On each invocation of a target program: dump x1..x4 + deref buffers; on leave dump outbuf.
// Learn pool (SM3); flag any invocation whose in/out contains a pool slot16 => THAT program produces it.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const TARGETS=null; // null => capture ALL programs (find which outputs slot16)
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function derefs(p){ // 2-level pointer-chase, dump bytes at each node (collect all hex for post-match)
  const out=[]; try{ for(let i=0;i<8;i++){ let q; try{ q=ptr(p).add(i*8).readPointer(); }catch(e){ break; }
    let d=null; try{ d=hx(q,32); }catch(e){}
    const sub=[]; try{ for(let j=0;j<6;j++){ let q2; try{ q2=q.add(j*8).readPointer(); }catch(e){ break; }
      let d2=null; try{ d2=hx(q2,32); }catch(e){} if(d2) sub.push(d2); } }catch(e){}
    out.push({off:i*8, ptr:q.toString(), data:d, sub:sub}); } }catch(e){}
  return out;
}
const pool={}; let cap=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    const x0=a[0]; let off; try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; off=x0.sub(base).toInt32(); }catch(e){ return; }
    if(TARGETS && !TARGETS[off]) return;
    if(cap>=500) return;
    this.prog='0x'+off.toString(16);
    this.x4=a[4];
  },onLeave(){
    if(!this.prog||cap>=250) return; cap++;
    const out=derefs(this.x4); const outflat=hx(this.x4,64);
    send({t:'io', prog:this.prog, x4:this.x4.toString(), outflat:outflat, out:out});
  }});
  setTimeout(function(){ send({t:'pool', pool:Object.keys(pool)}); }, 12000);
  setTimeout(function(){ send({t:'pool', pool:Object.keys(pool)}); }, 30000);
  send({t:'info',msg:'vm-cap600 installed, targets='+Object.keys(TARGETS).map(x=>'0x'+parseInt(x).toString(16)).join(',')});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
