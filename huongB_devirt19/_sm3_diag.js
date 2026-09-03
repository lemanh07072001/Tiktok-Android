// _sm3_diag.js — RAW diagnostic on SM3-tail (0xa0748). Reports EVERY completed SM3 message
// (mlen, tail bytes, device_platform?, the 16B at mlen-17) regardless of filters, plus fire counters.
// Purpose: see whether the register sign fires and what its real format/slot16 looks like on the AVD build.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const chain={};
let fireN=0, freshN=0, completeN=0, reported=0;
function hxab(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function hx(a){let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base;
  Interceptor.attach(base.add(SM3),{onEnter(){
    fireN++;
    const tid=this.threadId; let st,inp;
    try{ st=hxab(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE){ freshN++; chain[tid]=Array.from(inp); }
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
    else return;
    const a=chain[tid], L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16 && mlen<L)) return;
    if(a[mlen]!==0x80) return;            // not yet the terminal block for this message
    completeN++;
    // completed message -> report (capped)
    if(reported<40){
      reported++;
      const hasDP = ( ()=>{ let f=''; for(let i=0;i<Math.min(mlen,4096);i++) f+=String.fromCharCode(a[i]); return f.indexOf('device_platform=')>=0; } )();
      const tail = a.slice(Math.max(0,mlen-20), mlen);      // last 20 bytes incl terminator
      const s16  = a.slice(mlen-17, mlen-1);                 // candidate slot16
      let printable=0; for(const b of s16) if(b>=0x20&&b<=0x7e) printable++;
      send({t:'msg', n:completeN, tid:tid, mlen:mlen, dp:hasDP, term:'0x'+a[mlen-1].toString(16),
            tail:hx(tail), s16:hx(s16), s16pr:printable});
    }
    delete chain[tid];
  }});
  send({t:'info', msg:'sm3-diag installed base='+base});
  // periodic counters
  setInterval(function(){ send({t:'ctr', fire:fireN, fresh:freshN, complete:completeN}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
