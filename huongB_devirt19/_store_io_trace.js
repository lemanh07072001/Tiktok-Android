'use strict';
// STORE I/O TRACER — stop guessing crypt offsets; let the WRITE path reveal the truth.
// Hook libc open/openat (fd<->path for .ms*), write/pwrite64/writev (dump ciphertext
// being written + backtrace). The backtrace frame inside libmetasec_ov.so = the real
// store serialize/encrypt fn. Also capture READ side for decrypt. ATTACH only, NO re-register.
var MOD='libmetasec_ov.so', modBase=null, modSz=0;
Process.enumerateModules().forEach(function(m){ if(m.name===MOD){modBase=m.base; modSz=m.size;} });
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var fdmap={}, log=[], CAP=400, MAXBUF=8192;
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
function inMeta(a){ return modBase && a.compare(modBase)>=0 && a.compare(modBase.add(modSz))<0; }
function bt(ctx){ try{ return Thread.backtrace(ctx,Backtracer.ACCURATE).map(function(a){
    if(inMeta(a)) return 'META+0x'+a.sub(modBase).toString(16);
    var m=Process.findModuleByAddress(a); return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();
  }); }catch(e){ return []; } }
function metaOff(ctx){ var b=Thread.backtrace(ctx,Backtracer.ACCURATE); for(var i=0;i<b.length;i++){ if(inMeta(b[i])) return b[i].sub(modBase).toString(16); } return null; }

function hook(name){ var p=Module.findGlobalExportByName?Module.findGlobalExportByName(name):null;
  if(!p){ send({tag:'NOFN',fn:name}); return; } return p; }

// open/openat -> learn fd for store paths
var pOpen=hook('open'); if(pOpen) Interceptor.attach(pOpen,{ onEnter:function(a){ try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
  onLeave:function(r){ if(this.path){var n=this.path.split('/').pop(); if(STORE_RE.test(n)){var fd=r.toInt32(); if(fd>=0){fdmap[fd]=n; send({tag:'OPEN',fd:fd,store:n});}}} } });
var pOpenat=hook('openat'); if(pOpenat) Interceptor.attach(pOpenat,{ onEnter:function(a){ try{this.path=a[1].readUtf8String();}catch(e){this.path=null;} },
  onLeave:function(r){ if(this.path){var n=this.path.split('/').pop(); if(STORE_RE.test(n)){var fd=r.toInt32(); if(fd>=0){fdmap[fd]=n; send({tag:'OPEN',fd:fd,store:n});}}} } });

function onWrite(a){ var fd=a[0].toInt32(); if(!(fd in fdmap)) return null;
  var buf=a[1], len=a[2].toInt32(); if(len<=0||len>MAXBUF) len=Math.min(len,MAXBUF);
  return {fd:fd,store:fdmap[fd],buf:buf,len:len}; }
var pWrite=hook('write'); if(pWrite) Interceptor.attach(pWrite,{ onEnter:function(a){ this.w=onWrite(a);
    if(this.w){ this.mo=metaOff(this.context); this.bt=bt(this.context); } },
  onLeave:function(){ if(!this.w||log.length>=CAP) return; var w=this.w;
    var head=b2h(rd(w.buf,Math.min(w.len,64))), full=w.len<=512?b2h(rd(w.buf,w.len)):null;
    log.push({t:'WRITE',store:w.store,len:w.len,metaOff:this.mo,head:head,full:full,bt:this.bt});
    send({tag:'WRITE',store:w.store,len:w.len,metaOff:this.mo,head:head}); } });
var pPw=hook('pwrite64'); if(pPw) Interceptor.attach(pPw,{ onEnter:function(a){ this.w=onWrite(a);
    if(this.w){ this.mo=metaOff(this.context); this.bt=bt(this.context); } },
  onLeave:function(){ if(!this.w||log.length>=CAP) return; var w=this.w;
    var head=b2h(rd(w.buf,Math.min(w.len,64))), full=w.len<=512?b2h(rd(w.buf,w.len)):null;
    log.push({t:'PWRITE',store:w.store,len:w.len,metaOff:this.mo,head:head,full:full,bt:this.bt});
    send({tag:'WRITE',store:w.store,len:w.len,metaOff:this.mo,head:head}); } });

// read side (decrypt source)
function onRead(a){ var fd=a[0].toInt32(); if(!(fd in fdmap)) return null; return {fd:fd,store:fdmap[fd],buf:a[1],len:a[2].toInt32()}; }
var pRead=hook('read'); if(pRead) Interceptor.attach(pRead,{ onEnter:function(a){ this.r=onRead(a); if(this.r) this.bt=bt(this.context); },
  onLeave:function(r){ if(!this.r||log.length>=CAP) return; var n=r.toInt32(); if(n<=0) return; var rd_=this.r;
    var head=b2h(rd(rd_.buf,Math.min(n,64)));
    log.push({t:'READ',store:rd_.store,len:n,head:head,bt:this.bt}); send({tag:'READ',store:rd_.store,len:n,head:head}); } });

// close -> drop fd
var pClose=hook('close'); if(pClose) Interceptor.attach(pClose,{ onEnter:function(a){ var fd=a[0].toInt32(); if(fd in fdmap) delete fdmap[fd]; } });

send({tag:'READY',base:modBase?modBase.toString():null,fns:['open','openat','write','pwrite64','read','close']});
rpc.exports={ status:function(){return {events:log.length,fds:Object.keys(fdmap).length};},
  dump:function(){return log;}, clear:function(){log=[];return true;} };
