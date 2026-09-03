'use strict';
// dig-key v5: capture hash-primitive I/O during slot16 production.
// Hook producer (gate), SM3 driver 0x9fdac. Dump SM3 input buffer(s) + output digest. Tie to slot16 via DEC.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4, SM3=0x9fdac;
let base=null; const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function cstr(p){try{return p.readUtf8String(140);}catch(e){try{return p.readCString(140);}catch(e2){return null;}}}
function tgt(p,n){try{const q=p.readPointer();return{ptr:q.toString(),hex:hx(q,n),asc:asc(q,n)};}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context,tid=this.threadId;
      let sel=null;try{sel=(parseInt(c.x1.toString())&0xffffffff);}catch(e){}
      let url=cstr(c.x2);if(url===null){try{url=cstr(c.x2.readPointer());}catch(e){}}
      active[tid]={sel,url,sm3:[]};},
    onLeave(){const tid=this.threadId,a=active[tid];if(a){
      send({t:'PROD',tid,ts:Date.now(),sel:a.sel,url:a.url,sm3:a.sm3});delete active[tid];}}
  });
  Interceptor.attach(base.add(SM3),{
    onEnter(){const tid=this.threadId,a=active[tid];if(!a)return;const c=this.context;
      this._tid=tid;this._c=c;
      // capture args generically: regs + follow x0..x3 as ptr, and read x1/x2 as possible length
      let len=null;try{len=parseInt(c.x1.toString())&0xffffffff;}catch(e){}
      this._rec={
        x0:c.x0.toString(),x1:c.x1.toString(),x2:c.x2.toString(),x3:c.x3.toString(),
        // input candidates: x0 as data buffer (len from x1), plus follows
        in_x0:{hex:hx(c.x0,Math.min(len||64,192)),asc:asc(c.x0,Math.min(len||64,192))},
        f0:tgt(c.x0,96),f1:tgt(c.x1,96),f2:tgt(c.x2,64),f3:tgt(c.x3,64),
        len_x1:len,
      };},
    onLeave(retval){const a=active[this._tid];if(!a||!this._rec)return;const c=this._c;
      // output digest candidates: x0 buffer after (in-place), x2/x3 targets, retval target
      this._rec.out_x0=hx(c.x0,48);
      this._rec.out_x2=tgt(c.x2,48); this._rec.out_x3=tgt(c.x3,48);
      try{this._rec.out_ret=hx(ptr(retval),48);}catch(e){}
      if(a.sm3.length<30)a.sm3.push(this._rec);}
  });
  Interceptor.attach(base.add(DEC),{
    onEnter(){const c=this.context;try{this._x8=c.x8;this._x0=c.x0;this._inlen=ptr(c.x0).add(4).readU32();}catch(e){this._x8=null;}},
    onLeave(){if(!this._x8)return;try{
      const outlen=ptr(this._x8).add(4).readU32();if(outlen!==16)return;
      const dptr=ptr(this._x8).add(8).readPointer();const slot16=hx(dptr,16);
      let inp=null;try{const ip=ptr(this._x0).add(8).readPointer();inp=asc(ip,this._inlen);}catch(e){}
      const tid=this.threadId,a=active[tid];
      send({t:'DEC',tid,ts:Date.now(),slot16,hexstr:inp,url:a&&a.url});
    }catch(e){}}
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){try{this.p=a[0].readCString();}catch(e){}},
  onLeave(){if(this.p&&this.p.indexOf(SO)>=0) install();}});
setInterval(()=>send({t:'mon'}),8000);
