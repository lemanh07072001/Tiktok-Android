'use strict';
// STORE I/O PROBE — reader-agnostic. Hooks libc openat/open/read/pread/mmap to
// catch the store file access no matter which function reads it, captures the
// ciphertext, arms a window, and ties the in-window AES KSCH/EINIT to it = key.
// Also samples 0xe2df0 paths to confirm whether it's ever the store reader.
var MOD='libmetasec_ov.so';
var OFF={RDR:0xe2df0,KSCH:0x1591bc,EINIT:0x159d60,BENC:0x159d1c,BDEC:0x15997c,CBCE:0x159de4,CBCD:0x159f58};
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var DIR_RE=/(mssdk|\.msdata|\/ov\/)/i;
var seq=0, armUntil=0, curStore=null, log=[], installed=false, fds={}, rdrPaths=[], openPaths=[];

function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
function resolveExport(name){
  try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(name);}catch(e){}
  try{ if(Module.findGlobalExportByName){var p=Module.findGlobalExportByName(name);if(p)return p;}}catch(e){}
  var r=null; try{Process.enumerateModules().forEach(function(m){if(r)return;try{var e=(m.findExportByName?m.findExportByName(name):null);if(e)r=e;}catch(_){}});}catch(e){}
  return r;
}
function noteOpen(path, fd){
  if(!path) return;
  var name=path.split('/').pop();
  var isStore=STORE_RE.test(name), isDir=DIR_RE.test(path);
  if(!isStore && !isDir) return;
  if(openPaths.length<40) openPaths.push(path);
  if(fd>=0 && (isStore||isDir)) fds[fd]={name:name,path:path,store:isStore};
  if(isStore){ curStore=name; armUntil=Date.now()+400; seq++; log.push({t:'OPEN',seq:seq,store:name,path:path,fd:fd}); send({tag:'OPEN',seq:seq,store:name,fd:fd}); }
}
function noteRead(fd, buf, n){
  var f=fds[fd]; if(!f) return;
  if(f.store){ curStore=f.name; armUntil=Date.now()+400; }
  var cap=(buf&&n>0&&n<8192)?rd(buf,n):null;
  seq++; log.push({t:'READ',seq:seq,store:f.store?f.name:null,path:f.path,n:n,cipher:cap?b2h(cap):null});
  send({tag:'READ',seq:seq,store:f.store?f.name:null,n:n});
}

function installLibc(){
  var oat=resolveExport('openat');
  if(oat) Interceptor.attach(oat,{ onEnter:function(a){ try{this.path=a[1].readUtf8String();}catch(e){this.path=null;} }, onLeave:function(r){ noteOpen(this.path, r.toInt32()); } });
  var op=resolveExport('open');
  if(op) Interceptor.attach(op,{ onEnter:function(a){ try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} }, onLeave:function(r){ noteOpen(this.path, r.toInt32()); } });
  ['read','pread','pread64','__read_chk'].forEach(function(fn){
    var p=resolveExport(fn); if(!p) return;
    Interceptor.attach(p,{ onEnter:function(a){ this.fd=a[0].toInt32(); this.buf=a[1]; }, onLeave:function(r){ var n=r.toInt32(); if(n>0 && fds[this.fd]) noteRead(this.fd,this.buf,n); } });
  });
  var cl=resolveExport('close');
  if(cl) Interceptor.attach(cl,{ onEnter:function(a){ var fd=a[0].toInt32(); if(fds[fd]) delete fds[fd]; } });
}
function installMeta(base){
  function A(o){return base.add(o);}
  Interceptor.attach(A(OFF.RDR),{ onEnter:function(a){ try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} }, onLeave:function(){ if(this.path && rdrPaths.length<40) rdrPaths.push(this.path); if(this.path && DIR_RE.test(this.path)){ var nm=this.path.split('/').pop(); if(STORE_RE.test(nm)){curStore=nm;armUntil=Date.now()+400;} seq++; log.push({t:'RDR',seq:seq,store:STORE_RE.test(nm)?nm:null,path:this.path}); send({tag:'RDR',seq:seq,path:this.path}); } } });
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){ var kb=-1;try{kb=a[2].toInt32();}catch(e){} var uk=null;try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){} var w=(Date.now()<=armUntil);seq++;log.push({t:'KSCH',seq:seq,win:w,store:w?curStore:null,keyBytes:kb,userKey:uk});send({tag:'KSCH',seq:seq,win:w,keyBytes:kb}); } });
  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){ var kb=-1;try{kb=a[2].toInt32();}catch(e){} var uk=null,iv=null;try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){}try{iv=b2h(rd(a[3],16));}catch(e){} var w=(Date.now()<=armUntil);seq++;log.push({t:'EINIT',seq:seq,win:w,store:w?curStore:null,keyBytes:kb,userKey:uk,iv:iv});send({tag:'EINIT',seq:seq,win:w,keyBytes:kb}); } });
  function hb(off,nm){ Interceptor.attach(A(off),{ onEnter:function(a){this.w=(Date.now()<=armUntil);if(!this.w)return;this.i=a[1];this.o=a[2];},onLeave:function(){if(!this.w)return;seq++;log.push({t:nm,seq:seq,store:curStore,in16:b2h(rd(this.i,16)),out16:b2h(rd(this.o,16))});}}); }
  hb(OFF.BENC,'BENC');hb(OFF.BDEC,'BDEC');hb(OFF.CBCE,'CBCE');hb(OFF.CBCD,'CBCD');
}
function findBase(){var b=null;try{Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});}catch(e){}return b;}
function tryInstall(){ if(installed)return true; var b=findBase(); if(!b)return false; installed=true; installMeta(b); send({tag:'READY',base:b.toString()}); return true; }

installLibc();  // libc hooks are resolvable at park time (libc always mapped)
['android_dlopen_ext','__loader_android_dlopen_ext','dlopen'].forEach(function(fn){ var p=resolveExport(fn); if(p) try{Interceptor.attach(p,{onLeave:function(){ if(!installed) tryInstall(); }});}catch(e){} });
rpc.exports={ dump:function(){return log;}, meta:function(){return {installed:installed,rdrPaths:rdrPaths,openPaths:openPaths,events:log.length};} };
if(!tryInstall()){ var iv=setInterval(function(){ if(tryInstall()) clearInterval(iv); },20); }
send({tag:'BOOT',msg:'io-probe armed (libc+dlopen)'});
