'use strict';
// STORE ORACLE v8c — for JDWP-wait cold start. App is BLOCKED before native init when
// this loads, so hooks are guaranteed in place before the first store read.
//  - libc file syscalls (open/openat/read/pread/readv/close) -> raw store ciphertext by fd.
//  - dlopen/android_dlopen_ext -> install metasec hooks SYNCHRONOUSLY the moment libmetasec maps
//    (before the app can run its post-load store read).
//  - metasec: RDR(reader), EINIT(AES key/iv), AES/CBC blocks, DISP(mode). OBSERVE-ONLY.
var LIBC=Process.getModuleByName('libc.so');
function L(n){try{return LIBC.getExportByName(n);}catch(e){return null;}}
var OFF={RDR:0xe2df0,DISP:0x10dc18,BENC:0x159d1c,BDEC:0x15997c,CBCE:0x159de4,CBCD:0x159f58,EINIT:0x159d60};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){try{return p.readByteArray(n);}catch(e){return null;}}
var SD='mssdk/ov';
function isStore(p){return p&&(p.indexOf(SD)>=0||/\.ms[a-z0-9]*[_.]/.test((''+p).split('/').pop()));}
var armUntil=0,curStore=null,events=[],ring=[],RINGMAX=1000,fdMap={};
function pushRing(o){ring.push(o);if(ring.length>RINGMAX)ring.shift();}
function arm(name){curStore=name;armUntil=Date.now()+300;}

function hookOpen(fn){var f=L(fn);if(!f)return;Interceptor.attach(f,{
  onEnter:function(a){try{this.p=(fn==='openat')?a[1].readUtf8String():a[0].readUtf8String();}catch(e){this.p=null;}},
  onLeave:function(r){if(this.p&&isStore(this.p)){var fd=r.toInt32();if(fd>=0){fdMap[fd]=this.p;arm(this.p.split('/').pop());send({tag:'OPEN',via:fn,path:this.p.split('/').pop(),fd:fd});}}}});}
hookOpen('open');hookOpen('openat');
function hookRead(fn,bufIdx){var f=L(fn);if(!f)return;Interceptor.attach(f,{
  onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd]){this.fd=fd;this.buf=a[bufIdx];}},
  onLeave:function(r){if(this.fd!==undefined){var n=r.toInt32();if(n>0){var h=b2h(rd(this.buf,Math.min(n,4096)));var name=fdMap[this.fd].split('/').pop();arm(name);
    events.push({t:'READ',via:fn,store:name,n:n,cipher:h});send({tag:'READ',via:fn,store:name,n:n,head:h?h.slice(0,32):null});}}}});}
hookRead('read',1);hookRead('pread',1);hookRead('pread64',1);hookRead('readv',1);
var cf=L('close');if(cf)Interceptor.attach(cf,{onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd])delete fdMap[fd];}});

var installed=false;
function installMeta(mbase){
  if(installed)return; installed=true;
  function M(o){return mbase.add(o);}
  function hookBlk(off,name){Interceptor.attach(M(off),{
    onEnter:function(a){this.i=a[1];this.o=a[2];this.win=(Date.now()<=armUntil);this.st=curStore;},
    onLeave:function(){var IN=b2h(rd(this.i,16)),OUT=b2h(rd(this.o,16));pushRing({ts:Date.now(),name:name,in:IN,out:OUT,st:this.st});
      if(this.win){events.push({t:name,store:this.st,in16:IN,out16:OUT});send({tag:name,store:this.st,in16:IN,out16:OUT});}}});}
  hookBlk(OFF.BENC,'BENC');hookBlk(OFF.BDEC,'BDEC');hookBlk(OFF.CBCE,'CBCE');hookBlk(OFF.CBCD,'CBCD');
  Interceptor.attach(M(OFF.DISP),{onEnter:function(a){var m=-1;try{m=a[0].readPointer().readU32();}catch(e){}pushRing({ts:Date.now(),name:'DISP',mode:m,st:curStore});
    if(Date.now()<=armUntil){events.push({t:'DISP',store:curStore,mode:m});send({tag:'DISP',store:curStore,mode:m});}}});
  Interceptor.attach(M(OFF.EINIT),{onEnter:function(a){var kb=-1;try{kb=a[2].toInt32();}catch(e){}
    var uk=null,iv=null;try{uk=b2h(rd(a[1],kb>0&&kb<=32?kb:16));}catch(e){}try{iv=b2h(rd(a[3],16));}catch(e){}
    var inw=(Date.now()<=armUntil);pushRing({ts:Date.now(),name:'EINIT',key:uk,iv:iv,st:inw?curStore:null});
    var ev={t:'EINIT',win:inw,store:inw?curStore:null,kb:kb,key:uk,iv:iv};events.push(ev);
    send({tag:'EINIT',win:inw,store:ev.store,kb:kb,key:uk,iv:iv});}});
  Interceptor.attach(M(OFF.RDR),{
    onEnter:function(a){this.pbuf=a[1];this.plen=a[2];try{this.path=a[0].readUtf8String();}catch(e){this.path=null;}},
    onLeave:function(){if(!this.path||!isStore(this.path))return;var name=this.path.split('/').pop();
      var len=0,buf=null;try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
      try{buf=this.pbuf.readPointer();}catch(e){}
      var full=(buf&&len)?b2h(rd(buf,Math.min(len,4096))):null;arm(name);
      events.push({t:'RDR',store:name,len:len,cipher:full});
      send({tag:'RDR',store:name,len:len,head:full?full.slice(0,48):null});}});
  send({tag:'META_READY',mbase:mbase.toString()});
}
// try now (in case already mapped), else on dlopen
var m0=Process.findModuleByName('libmetasec_ov.so'); if(m0)installMeta(m0.base);
['android_dlopen_ext','dlopen'].forEach(function(fn){var f=L(fn);if(!f)return;Interceptor.attach(f,{
  onLeave:function(){if(installed)return;var m=Process.findModuleByName('libmetasec_ov.so');if(m)installMeta(m.base);}});});
var poll=setInterval(function(){if(installed){clearInterval(poll);return;}var m=Process.findModuleByName('libmetasec_ov.so');if(m){installMeta(m.base);clearInterval(poll);}},30);

rpc.exports={dump:function(){return {events:events,installed:installed};},ring:function(){return ring.slice(-120);}};
send({tag:'READY8c'});
