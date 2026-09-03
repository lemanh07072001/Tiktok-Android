'use strict';
// dig-key v4: pin down consumer 0x89320 x1 (candidate KEY or OUTPUT). Read x1 as {size@0? , dataptr@+8},
// dump target onEnter & onLeave; also dump ctx+0x10 (rolling) once. Tie to slot16/hexstr via DEC.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4, CONS=0x89320;
let base=null; const active={};
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function cstr(p){try{return p.readUtf8String(140);}catch(e){try{return p.readCString(140);}catch(e2){return null;}}}
function tgt(p,off,n){try{const q=p.add(off).readPointer();return{ptr:q.toString(),hex:hx(q,n),asc:asc(q,n)};}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context,tid=this.threadId;
      let sel=null;try{sel=(parseInt(c.x1.toString())&0xffffffff);}catch(e){}
      let url=cstr(c.x2); if(url===null){try{url=cstr(c.x2.readPointer());}catch(e){}}
      active[tid]={sel,url,cons:[]};},
    onLeave(){const tid=this.threadId,a=active[tid];if(a){
      send({t:'PROD',tid,ts:Date.now(),sel:a.sel,url:a.url,cons:a.cons});delete active[tid];}}
  });
  Interceptor.attach(base.add(CONS),{
    onEnter(){const tid=this.threadId,a=active[tid];if(!a)return;const c=this.context;
      this._tid=tid;this._x1=c.x1;
      this._rec={
        x1:c.x1.toString(),x3:c.x3.toString(),
        x1_raw:hx(c.x1,24),
        // interpret x1 as std::string-like: try dataptr at +0, +8, +16
        x1_p0:tgt(c.x1,0,32), x1_p8:tgt(c.x1,8,32), x1_p16:tgt(c.x1,16,32),
      };},
    onLeave(retval){const a=active[this._tid];if(!a||!this._rec)return;const p=this._x1;
      this._rec.x1_raw_out=hx(p,24);
      this._rec.x1_p0_out=tgt(p,0,40); this._rec.x1_p8_out=tgt(p,8,40); this._rec.x1_p16_out=tgt(p,16,40);
      this._rec.ret=retval?retval.toString():null;
      if(a.cons.length<8)a.cons.push(this._rec);}
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
