'use strict';
// _drv_seq.js — capture COMPLETE feed sequence into the hash driver up to a 16B emit.
// DRV(0x9fdac)(x0=buf, x1=len). Per-thread, accumulate all chunks; on nonzero 16B emit,
// dump the whole ordered sequence since last emit (full bytes, capped).
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null;
const seqs={};           // tid -> [ {len, b64} ]
let nDump=0; const MAX=3;
const CHUNK_CAP=2048, TOTAL_CAP=16384;
function b64(p,n){ try{ return ptr(p).readByteArray(n);}catch(e){return null;} }
function toB64(ab){ // frida: use built-in
  const u=new Uint8Array(ab); let bin='';
  for(let i=0;i<u.length;i++) bin+=String.fromCharCode(u[i]);
  return (typeof btoa!=='undefined')?btoa(bin):null;
}
function hexOf(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(DRV),{ onEnter(a){ try{
    const len=this.context.x1.toInt32()&0xffffffff;
    const tid=this.threadId, x0=this.context.x0;
    if(!seqs[tid]) seqs[tid]=[];
    // is this the 16B emit?
    if(len===16){
      const val=hexOf(x0,16);
      if(val && !/^0+$/.test(val) && nDump<MAX){
        nDump++;
        const arr=seqs[tid]; let tot=0; const out=[];
        for(const c of arr){ tot+=c.len; out.push(c); if(tot>TOTAL_CAP) break; }
        send({t:'SEQ', slot16:val, nchunks:arr.length, chunks:out});
        seqs[tid]=[]; // reset after emit
        return;
      }
      // zero or over-limit 16B: still record then reset
      seqs[tid]=[]; return;
    }
    // record chunk (cap size)
    const rn=Math.min(len,CHUNK_CAP);
    const ab=b64(x0,rn); if(!ab) return;
    seqs[tid].push({len:len, cap:rn, b64:toB64(ab)});
    // prevent unbounded growth
    if(seqs[tid].length>64) seqs[tid].shift();
  }catch(e){} }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',nDump:nDump}),4000);
