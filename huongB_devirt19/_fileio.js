'use strict';
// Global libc hook: catch open/read of .msp_589c and dump the raw + track buffer
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
const fds={};
const openat=Module.findGlobalExportByName('openat');
const openf=Module.findGlobalExportByName('open');
const readf=Module.findGlobalExportByName('read');
if(openat)Interceptor.attach(openat,{
  onEnter(a){try{this.n=a[1].readCString();}catch(e){}},
  onLeave(r){if(this.n&&(this.n.indexOf('.msp_')>=0||this.n.indexOf('.mss_')>=0||this.n.indexOf('.msf3')>=0)){fds[r.toInt32()]=this.n;send({t:'OPEN',name:this.n,fd:r.toInt32()});}}
});
if(openf)Interceptor.attach(openf,{
  onEnter(a){try{this.n=a[0].readCString();}catch(e){}},
  onLeave(r){if(this.n&&(this.n.indexOf('.msp_')>=0||this.n.indexOf('.mss_')>=0||this.n.indexOf('.msf3')>=0)){fds[r.toInt32()]=this.n;send({t:'OPEN',name:this.n,fd:r.toInt32()});}}
});
if(readf)Interceptor.attach(readf,{
  onEnter(a){this.fd=a[0].toInt32();this.buf=a[1];},
  onLeave(r){const nm=fds[this.fd];const n=r.toInt32();if(nm&&n>0){send({t:'READ',name:nm,n:n,data:hx(this.buf,Math.min(n,512))});}}
});
send({t:'info',msg:'file io hook installed'});
