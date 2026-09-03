// _callout_data.js — characterize the 2 native call-outs' OUTPUT (the value the singleton-getter returns).
// getter 0x13af90: method1@0x13b010 -> [sp]->[x20+0x10]; method2@0x13b034; returns [x20+0x10] via [x19+8].
// Hook 0x13b04c (getter tail): read x20 + [x20..+0x20] + deref [x20+0x10]. Reading memory here is non-perturbing.
// Question: does the returned value VARY per-request (seed-dependent=crypto) or is it device-stable (context)?
'use strict';
const SO='libmetasec_ov.so', TAIL=0x13b04c, SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; let n=0; const chain={};
  Interceptor.attach(base.add(TAIL),{onEnter(){
    if(n>=14) return; n++;
    const c=this.context; const x20=c.x20;
    let ret=null, retderef=null, ctx=null;
    try{ ctx=rd(x20,0x20); const rp=x20.add(0x10).readPointer(); ret=rp.toString(); retderef=rd(rp,64);}catch(e){}
    send({t:'co', n:n, tid:this.threadId, x20:x20.toString(), ctx:ctx, ret:ret, retderef:retderef});
  }});
  // also SM3 #19 slot16 to correlate
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80){return;}
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) send({t:'slot',tid:tid,slot16:slot});
    delete chain[tid];
  }});
  send({t:'info',msg:'callout-data installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
