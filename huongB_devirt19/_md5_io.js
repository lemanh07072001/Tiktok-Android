'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return s;}catch(e){return'ERR';}}
let hits=0;
// md5 one-shot 0x15b594. Capture input on enter, output on leave.
Interceptor.attach(base.add(0x15b594),{
  onEnter(){
    if(hits>=40)return;
    const c=this.context;
    const len=c.x1.toInt32();
    this.len=len; this.dataptr=c.x0; this.outptr=c.x2;
    this.input = (len>0&&len<8192)?asc(c.x0,Math.min(len,300)):null;
    this.inhex = (len>0&&len<8192)?hx(c.x0,Math.min(len,64)):null;
  },
  onLeave(ret){
    if(hits>=40)return; hits++;
    // output md5 = 16 bytes. Try x2 (3rd arg) and return value as out ptr.
    let out_x2=hx(this.outptr,16);
    let out_ret=hx(ret,16);
    send({t:'MD5IO',n:hits,len:this.len,input:this.input,inhex:this.inhex,md5_x2:out_x2,md5_ret:out_ret});
  }
});
send({t:'info',msg:'md5 io hook installed'});
