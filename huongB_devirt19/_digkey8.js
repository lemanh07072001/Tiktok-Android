'use strict';
// _digkey8 — decisive: dump ctx_session at PRODUCER entry + resulting hexdigest at leave.
// Goal: determine if slot16 is CACHED in ctx_session (pre-exists) or COMPUTED live.
const SO='libmetasec_ov.so';
const PROD=0x879d8;
let base=null,lo=null,hi=null;
function inMod(p){try{return p.compare(lo)>=0&&p.compare(hi)<0;}catch(e){return false;}}
function hexbuf(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
// read libc++ std::string at sret pointer (long mode: cap@0,len@8,data@16; short: len=[0]>>1,data@1)
function rdstr(p){
  try{
    const b0=p.readU8();
    if(b0&1){ // long
      const len=p.add(8).readU64().toNumber();
      const data=p.add(16).readPointer();
      if(len>0&&len<4096){const a=new Uint8Array(data.readByteArray(len));let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return {mode:'long',len:len,s:s};}
    } else {
      const len=b0>>1;
      if(len>0&&len<64){const a=new Uint8Array(p.add(1).readByteArray(len));let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return {mode:'short',len:len,s:s};}
    }
  }catch(e){}
  return null;
}
let count=0; const MAX=8; const recs=[];
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'loaded',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){
      if(count>=MAX)return;
      const c=this.context;
      this.sel=parseInt(c.x1.toString())&0xffffffff;
      this.x8=c.x8;               // sret pointer for returned std::string
      // dump ctx_session head
      this.ctxdump=hexbuf(c.x0,0x400);
      // follow pointer at x0+0x88 (seen in disasm: add x8,x0,#0x88)
      this.p88=null; this.d88=null;
      try{const pp=c.x0.add(0x88).readPointer(); if(inMod(pp)||true){this.p88=pp.toString(); this.d88=hexbuf(pp,0x100);}}catch(e){}
      // scan ctx head for embedded pointers, dump first few heap targets
      this.ptrs=[];
      try{
        for(let off=0;off<0x400;off+=8){
          const v=c.x0.add(off).readPointer();
          if(inMod(v)){continue;} // skip module ptrs (code/rodata)
          // heap-ish: readable, dump 0x40
          const d=hexbuf(v,0x40);
          if(d){this.ptrs.push({off:off,p:v.toString(),d:d});}
          if(this.ptrs.length>=6)break;
        }
      }catch(e){}
    },
    onLeave(r){
      if(count>=MAX)return;
      let out=null;
      try{out=rdstr(this.x8);}catch(e){}
      count++;
      recs.push({i:count,sel:this.sel,out:out,ctx:this.ctxdump,p88:this.p88,d88:this.d88,ptrs:this.ptrs});
      send({t:'REC',i:count,sel:this.sel,out:out?out.s:null});
      if(count>=MAX){send({t:'DUMP',recs:recs});}
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',count:count}),4000);
