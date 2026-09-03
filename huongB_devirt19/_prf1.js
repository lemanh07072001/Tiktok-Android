'use strict';
// _prf1.js — single-run capture: KEY blob (ctx.q4, 32B) + (message,slot16) pairs
// Goal: test slot16 = keyed-SM3(key, message) offline. Read-only, spawn.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,lo=null,hi=null;
let keySent=0, nPair=0; const MAXPAIR=6;
const lastMsg={};  // per-threadId last large feed bytes(hex)

function h(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;} }

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});

  Interceptor.attach(base.add(PROD),{
    onEnter(a){ try{ this._sel=this.context.x1.toInt32()&0xffffffff; this._x0=this.context.x0; }catch(e){ this._sel=-1; } },
    onLeave(r){
      if(this._sel!==0x171) return;
      try{
        const size=this._x0.add(0x18).readU32();
        const dptr=this._x0.add(0x20).readPointer();
        const blob=h(dptr, Math.min(Math.max(size,32),64));
        if(blob && !/^0+$/.test(blob) && keySent<3){
          keySent++;
          send({t:'KEY', size:size, dptr:''+dptr, blob:blob,
                q2:h(this._x0.add(0x10).readPointer(),32),   // other buffer
                ctx64:h(this._x0,64)});
        }
      }catch(e){ send({t:'KEYERR',e:''+e}); }
    }
  });

  Interceptor.attach(base.add(DRV),{
    onEnter(a){
      let len; try{ len=this.context.x1.toInt32()&0xffffffff; }catch(e){ return; }
      const tid=this.threadId;
      const x0=this.context.x0;
      if(len===16){
        const val=h(x0,16);
        if(val && !/^0+$/.test(val) && nPair<MAXPAIR){
          const msg=lastMsg[tid];
          if(msg){ nPair++; send({t:'PAIR', slot16:val, msglen:msg.length/2, msg:msg}); }
        }
      } else if(len>=32 && len<=4096){
        const b=h(x0,len);
        if(b) lastMsg[tid]=b;
      }
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',keySent:keySent,nPair:nPair}),5000);
