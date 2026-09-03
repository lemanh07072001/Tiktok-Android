'use strict';
// Hook libc open/read to catch .msp_589c file access and dump buffers.
const targets=['msp_589c','mss_9b8e','msp_092f'];
function matchName(s){ if(!s)return null; for(const t of targets) if(s.indexOf(t)>=0) return t; return null; }

const openImpl = Module.findGlobalExportByName('open') || Module.findGlobalExportByName('openat');
const fopenImpl = Module.findGlobalExportByName('fopen');
const readImpl  = Module.findGlobalExportByName('read');
const freadImpl = Module.findGlobalExportByName('fread');

const trackedFds = {};   // fd -> tag
const trackedFiles = {}; // FILE* -> tag

if (openImpl) Interceptor.attach(openImpl, {
  onEnter(a){ try{ this.name=a[0].readCString(); }catch(e){} },
  onLeave(ret){ const t=matchName(this.name); if(t){ trackedFds[ret.toInt32()]=t; send({t:'OPEN',name:this.name,fd:ret.toInt32(),tag:t}); } }
});
if (fopenImpl) Interceptor.attach(fopenImpl, {
  onEnter(a){ try{ this.name=a[0].readCString(); }catch(e){} },
  onLeave(ret){ const t=matchName(this.name); if(t && !ret.isNull()){ trackedFiles[ret.toString()]=t; send({t:'FOPEN',name:this.name,tag:t}); } }
});
if (readImpl) Interceptor.attach(readImpl, {
  onEnter(a){ this.fd=a[0].toInt32(); this.buf=a[1]; },
  onLeave(ret){ const t=trackedFds[this.fd]; const n=ret.toInt32();
    if(t && n>0){ try{ const u=new Uint8Array(this.buf.readByteArray(Math.min(n,512))); let h='';for(let i=0;i<u.length;i++)h+=('0'+u[i].toString(16)).slice(-2); send({t:'READ',tag:t,n:n,data:h}); }catch(e){} } }
});
if (freadImpl) Interceptor.attach(freadImpl, {
  onEnter(a){ this.buf=a[0]; this.size=a[1].toInt32(); this.nmemb=a[2].toInt32(); this.fp=a[3].toString(); },
  onLeave(ret){ const t=trackedFiles[this.fp]; const n=ret.toInt32()*this.size;
    if(t && n>0){ try{ const u=new Uint8Array(this.buf.readByteArray(Math.min(n,512))); let h='';for(let i=0;i<u.length;i++)h+=('0'+u[i].toString(16)).slice(-2); send({t:'FREAD',tag:t,n:n,data:h}); }catch(e){} } }
});
send({t:'info',msg:'PSK file hook installed'});
