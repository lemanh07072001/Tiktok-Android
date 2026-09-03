// _sm3_all.js — capture EVERY complete SM3 message (not just #19). Find the hash whose
// digest == slot16  => reveals F = SM3(preimage). Offline we recompute digests + match.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={};
  Interceptor.attach(base.add(SM3),{
    onEnter(){
      const tid=this.threadId; let st,inp;
      try{ this.stx0=this.context.x0; st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
      // message chain (standard-IV hashes)
      if(st===IV_LE) chain[tid]=Array.from(inp);
      else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
      if(chain[tid]){
        const a=chain[tid],L=a.length;
        if(L>=9){ let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
          if(mlen>=1 && mlen<L && a[mlen]===0x80 && mlen<=512){
            let msg=''; for(let i=0;i<mlen;i++) msg+=('0'+a[i].toString(16)).slice(-2);
            send({t:'sm3msg', tid:tid, mlen:mlen, msg:msg}); delete chain[tid];
          }
        }
      }
    },
    onLeave(){
      // output state after THIS block = candidate digest (catches keyed/custom-IV SM3)
      try{ const outst=hx(this.stx0.add(8).readByteArray(32)); send({t:'state', st:outst}); }catch(e){}
    }
  });
  send({t:'info',msg:'sm3-all installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
