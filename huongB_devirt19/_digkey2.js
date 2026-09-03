'use strict';
// dig-key v2: computed path. Dump ctx wide + find-node wide + consumer 0x89320 inputs.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4, RBFIND=0x8913c, CONS=0x89320;
let base=null; const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function follow(p,n){try{const q=p.readPointer();return {ptr:q.toString(),hex:hx(q,n),asc:asc(q,n)};}catch(e){return null;}}
function cstr(p){try{return p.readUtf8String(120);}catch(e){try{return p.readCString(120);}catch(e2){return null;}}}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context,tid=this.threadId;
      let sel=null;try{sel=(parseInt(c.x1.toString())&0xffffffff);}catch(e){}
      let url=cstr(c.x2); if(url===null){try{url=cstr(c.x2.readPointer());}catch(e){}}
      active[tid]={sel,url,x0:c.x0,
        ctx:hx(c.x0,0x100),
        p00:follow(c.x0.add(0x00),64),
        p10:follow(c.x0.add(0x10),64),
        p20:follow(c.x0.add(0x20),64),
        cons:[]};
    },
    onLeave(){const tid=this.threadId,a=active[tid]; if(a){
      send({t:'PROD',tid,ts:Date.now(),sel:a.sel,url:a.url,ctx:a.ctx,p00:a.p00,p10:a.p10,p20:a.p20,cons:a.cons});
      delete active[tid];
    }}
  });
  Interceptor.attach(base.add(CONS),{
    onEnter(){const tid=this.threadId,a=active[tid]; if(!a)return; const c=this.context;
      const rec={x0:c.x0.toString(),x1:c.x1.toString(),x2:c.x2.toString(),x3:c.x3.toString(),
        // thử x0,x1 as ptr→bytes (data being signed) + as len
        d0:hx(c.x0,64),a0:asc(c.x0,64),
        d0p:follow(c.x0,64),d1p:follow(c.x1,64),d2p:follow(c.x2,64)};
      if(a.cons.length<6)a.cons.push(rec);
    }
  });
  Interceptor.attach(base.add(DEC),{
    onEnter(){const c=this.context;try{this._x8=c.x8;this._x0=c.x0;this._inlen=ptr(c.x0).add(4).readU32();}catch(e){this._x8=null;}},
    onLeave(){if(!this._x8)return;try{
      const outlen=ptr(this._x8).add(4).readU32(); if(outlen!==16)return;
      const dptr=ptr(this._x8).add(8).readPointer(); const slot16=hx(dptr,16);
      let in_ascii=null;try{const ip=ptr(this._x0).add(8).readPointer();in_ascii=asc(ip,this._inlen);}catch(e){}
      const tid=this.threadId,a=active[tid];
      send({t:'DEC',tid,ts:Date.now(),slot16,hexstr:in_ascii,url:a&&a.url});
    }catch(e){}}
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){try{this.p=a[0].readCString();}catch(e){}},
  onLeave(){if(this.p&&this.p.indexOf(SO)>=0) install();}
});
setInterval(()=>send({t:'mon'}),8000);
