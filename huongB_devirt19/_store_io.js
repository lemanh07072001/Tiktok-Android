'use strict';
const SO='libmetasec_ov.so';
let mod=null, lo=null, hi=null;
const fds = {};
function inSO(p){ try{ return mod && p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){return false;} }
function bt(ctx){ try{ return Thread.backtrace(ctx, Backtracer.ACCURATE)
  .map(a=> inSO(a)? ('+0x'+a.sub(lo).toString(16)) : null).filter(x=>x).slice(0,10); }catch(e){return [];} }
function hd(p,len){ try{const b=p.readByteArray(len);const u=new Uint8Array(b);let h='';for(let i=0;i<u.length;i++)h+=('0'+u[i].toString(16)).slice(-2);return h;}catch(e){return 'ERR';} }
function isStore(s){ return s && (s.indexOf('.msp_')>=0||s.indexOf('.msfs_')>=0||s.indexOf('.msf3_')>=0||s.indexOf('/ss/')>=0); }
function libc(){ return Process.getModuleByName('libc.so'); }
function exp(name){ try{const p=libc().findExportByName(name); if(p) return p;}catch(e){} try{return Module.getGlobalExportByName(name);}catch(e){} return null; }

function setup(){
  mod=Process.findModuleByName(SO);
  if(mod){ lo=mod.base; hi=mod.base.add(mod.size); }
  const openat=exp('openat'), open=exp('open'), read=exp('read'), pread=exp('pread64');

  function hookOpen(fn, idx){
    if(!fn) return;
    Interceptor.attach(fn,{
      onEnter(a){ try{ this.path=a[idx].readUtf8String(); }catch(e){ this.path=null; } this.ctx=this.context; },
      onLeave(r){ const fd=r.toInt32(); if(this.path && isStore(this.path) && fd>=0){
        fds[fd]=this.path; send({t:'OPEN', path:this.path, fd:fd, bt:bt(this.ctx)}); }}
    });
  }
  hookOpen(openat,1); hookOpen(open,0);

  if(read) Interceptor.attach(read,{
    onEnter(a){ this.fd=a[0].toInt32(); this.buf=a[1]; this.ctx=this.context; },
    onLeave(r){ const fd=this.fd; if(fds[fd]!==undefined){ const nb=r.toInt32();
      if(nb>0) send({t:'READ', fd:fd, path:fds[fd], nb:nb, data:hd(this.buf,Math.min(nb,512)), bt:bt(this.ctx)}); }}
  });
  if(pread) Interceptor.attach(pread,{
    onEnter(a){ this.fd=a[0].toInt32(); this.buf=a[1]; this.ctx=this.context; },
    onLeave(r){ const fd=this.fd; if(fds[fd]!==undefined){ const nb=r.toInt32();
      if(nb>0) send({t:'PREAD', fd:fd, path:fds[fd], nb:nb, data:hd(this.buf,Math.min(nb,512)), bt:bt(this.ctx)}); }}
  });
  send({t:'ready', so: mod? mod.base.toString():'notloaded', openat:!!openat, read:!!read});
}
setup();
let tries=0;
const iv=setInterval(()=>{ tries++; if(!mod){ mod=Process.findModuleByName(SO); if(mod){lo=mod.base;hi=mod.base.add(mod.size); send({t:'info',msg:'SO loaded late',base:mod.base.toString()});}} if(tries>200) clearInterval(iv); }, 300);
