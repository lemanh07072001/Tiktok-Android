'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4;
let base=null,lo=null,hi=null;
const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function off(p){try{if(p.compare(lo)>=0&&p.compare(hi)<0)return p.sub(base).toInt32();}catch(e){}return null;}
// read libc++ std::string {len,data}
function rdstr(p){try{const b0=p.readU8();if(b0&1){const len=p.add(8).readU64().toNumber();const dp=p.add(16).readPointer();return{len,data:hx(dp,Math.min(len,64))};}else{const len=b0>>1;return{len,data:hx(p.add(1),Math.min(len,64))};}}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;
  base=m.base;lo=base;hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context;this._tid=this.threadId;this._x8=c.x8;active[this.threadId]={sret:c.x8};},
    onLeave(){const a=active[this._tid];if(a){/* x8 sret = output std::string of 32-hex */ a.out=rdstr(this._x8);}
      // emit producer summary once per call
      send({t:'PROD',tid:this._tid,out:a?a.out:null});
      delete active[this._tid];}
  });
  Interceptor.attach(base.add(DEC),{
    onEnter(){const tid=this.threadId;if(!active[tid])return;const c=this.context;
      // x0 = input std::string (the 32-hex). x8 = output buffer.
      const inp=rdstr(c.x0);
      let bt=null;try{bt=Thread.backtrace(c,Backtracer.ACCURATE).map(off).filter(x=>x!==null);}catch(e){bt=String(e);}
      send({t:'DEC',tid,inp,bt});}
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,500);}
