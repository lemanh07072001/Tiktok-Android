'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4;
const F1=0x151d40, F2=0x15009c, F3=0x14fe34; // neighbors around decode
let base=null,lo=null,hi=null;
const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function tgt(p,n){try{if(p.isNull())return null;return{p:p.toString(),hex:hx(p,n),asc:asc(p,n)};}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;
  base=m.base;lo=base;hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{onEnter(){active[this.threadId]=1;this._t=this.threadId;},onLeave(){delete active[this._t];}});
  function hookN(addr,name){
    Interceptor.attach(base.add(addr),{
      onEnter(){const tid=this.threadId;if(!active[tid])return;const c=this.context;
        this._n=name;this._c=c;this._x8=c.x8;
        this._in={x0:tgt(c.x0,96),x1:tgt(c.x1,96),x2:tgt(c.x2,64),x3:tgt(c.x3,64),
                  x1v:c.x1.toString(),x2v:c.x2.toString(),x8:c.x8.toString()};},
      onLeave(retval){if(!this._n)return;const c=this._c;
        const out={x0:tgt(c.x0,96),x8:tgt(this._x8,96),ret:tgt(ptr(retval),64)};
        send({t:'FN',name:this._n,in:this._in,out});this._n=null;}
    });
  }
  hookN(F1,'F1_151d40');hookN(F2,'F2_15009c');hookN(F3,'F3_14fe34');
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,500);}
