'use strict';
// dig-key v3: capture consumer 0x89320 TRUE I/O — x3 buffer onEnter (input) vs onLeave (hexstr32?),
// x1 as std::string, retval. Tie to slot16 via DEC. Goal: isolate PRF boundary (input->hexstr32).
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4, CONS=0x89320;
let base=null; const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function follow(p,n){try{const q=p.readPointer();return {ptr:q.toString(),hex:hx(q,n),asc:asc(q,n)};}catch(e){return null;}}
function cstr(p){try{return p.readUtf8String(140);}catch(e){try{return p.readCString(140);}catch(e2){return null;}}}
// libc++ std::string reader (SSO aware)
function rdstr(p){try{
  const b0=p.readU8();
  if(b0&1){ // long
    const len=p.add(8).readU64().toNumber();
    const dat=p.add(16).readPointer();
    return {mode:'long',len,s:asc(dat,Math.min(len,160)),hex:hx(dat,Math.min(len,160))};
  } else { // short: size=b0>>1, data at p+1
    const len=b0>>1;
    return {mode:'short',len,s:asc(p.add(1),Math.min(len,22)),hex:hx(p.add(1),Math.min(len,22))};
  }
}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context,tid=this.threadId;
      let sel=null;try{sel=(parseInt(c.x1.toString())&0xffffffff);}catch(e){}
      let url=cstr(c.x2); if(url===null){try{url=cstr(c.x2.readPointer());}catch(e){}}
      active[tid]={sel,url,cons:[]};
    },
    onLeave(){const tid=this.threadId,a=active[tid]; if(a){
      send({t:'PROD',tid,ts:Date.now(),sel:a.sel,url:a.url,cons:a.cons});
      delete active[tid];
    }}
  });
  Interceptor.attach(base.add(CONS),{
    onEnter(){const tid=this.threadId,a=active[tid]; if(!a)return; const c=this.context;
      this._tid=tid; this._x3=c.x3; this._x1=c.x1;
      const rec={
        x0:c.x0.toString(),x1:c.x1.toString(),x2:c.x2.toString(),x3:c.x3.toString(),
        // x1 as std::string (candidate canonical input) + raw
        x1str:rdstr(c.x1), x1raw:{hex:hx(c.x1,32),asc:asc(c.x1,32)},
        // x3 buffer BEFORE (input being signed)
        x3in:{hex:hx(c.x3,128),asc:asc(c.x3,128)},
        // follow x3 as ptr too
        x3follow:follow(c.x3,96),
      };
      this._rec=rec;
    },
    onLeave(retval){const a=active[this._tid]; if(!a||!this._rec)return;
      // x3 buffer AFTER (did hexstr32 get written here?)
      this._rec.x3out={hex:hx(this._x3,128),asc:asc(this._x3,128)};
      this._rec.x3outfollow=follow(this._x3,96);
      this._rec.ret=retval?retval.toString():null;
      if(a.cons.length<8)a.cons.push(this._rec);
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
