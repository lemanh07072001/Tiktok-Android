'use strict';
// libc-only file tracer. Logs EVERY open/openat + reads on store fds. No metasec hooks
// (avoids x16/x17 clobber crash). Decides: are stores read via libc, or direct syscall?
var LIBC=Process.getModuleByName('libc.so');
function L(n){try{return LIBC.getExportByName(n);}catch(e){return null;}}
function hx(p,n){try{var u=new Uint8Array(p.readByteArray(n)),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}catch(e){return null;}}
var fdMap={},opens=0,storeOpens=0;
function isStore(p){return p&&p.indexOf('mssdk/ov')>=0;}
function ho(fn,idx){var f=L(fn);if(!f)return;Interceptor.attach(f,{
  onEnter:function(a){try{this.p=a[idx].readUtf8String();}catch(e){this.p=null;}},
  onLeave:function(r){if(!this.p)return;opens++;
    if(isStore(this.p)||/\.ms[a-z0-9]*[_.]/.test(this.p.split('/').pop())){storeOpens++;var fd=r.toInt32();
      if(fd>=0)fdMap[fd]=this.p;send({tag:'SOPEN',via:fn,fd:fd,path:this.p});}
    else if(opens<=400 && this.p.indexOf('/data/')>=0){send({tag:'OPEN',via:fn,path:this.p});}
  }});}
ho('open',0);ho('openat',1);
function hr(fn,bi){var f=L(fn);if(!f)return;Interceptor.attach(f,{
  onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd]){this.fd=fd;this.buf=a[bi];}},
  onLeave:function(r){if(this.fd!==undefined){var n=r.toInt32();if(n>0)send({tag:'SREAD',via:fn,store:fdMap[this.fd].split('/').pop(),n:n,cipher:hx(this.buf,Math.min(n,4096))});}}});}
hr('read',1);hr('pread',1);hr('pread64',1);hr('readv',1);
var cf=L('close');if(cf)Interceptor.attach(cf,{onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd])delete fdMap[fd];}});
rpc.exports={stats:function(){return {opens:opens,storeOpens:storeOpens};}};
send({tag:'OPENREADY'});
