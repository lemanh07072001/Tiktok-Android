'use strict';
const SO='libmetasec_ov.so'; const DRV=0x9fdac;
let base=null; const seqs={}; let nDump=0; const MAX=6;
const CHUNK_CAP=4096;
function hexOf(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(DRV),{ onEnter(a){ try{
    const len=this.context.x1.toInt32()&0xffffffff;
    const tid=this.threadId, x0=this.context.x0;
    if(!seqs[tid]) seqs[tid]=[];
    if(len===16){
      const val=hexOf(x0,16);
      if(val && !/^0+$/.test(val) && nDump<MAX){
        nDump++;
        send({t:'SEQ', slot16:val, nchunks:seqs[tid].length, chunks:seqs[tid]});
        seqs[tid]=[]; return;
      }
      seqs[tid]=[]; return;
    }
    const rn=Math.min(len,CHUNK_CAP);
    const hx=hexOf(x0,rn); if(!hx) return;
    seqs[tid].push({len:len, cap:rn, hex:hx});
    if(seqs[tid].length>64) seqs[tid].shift();
  }catch(e){} }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',nDump:nDump}),4000);
