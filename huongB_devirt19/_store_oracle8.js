'use strict';
// STORE ORACLE v8 — COLD-START capture. On process start the SDK READS each store
// (RDR 0xe2df0) then DECRYPTS it. RDR arms a forward window; crypto firing just after
// RDR is the store decrypt. Also a ring look-back + libc read() capture + EINIT.
// Caught via spawn-gating (app launched by am start, paused at entry). ATTACH/OBSERVE only.

var MET=Process.getModuleByName('libmetasec_ov.so'); var mbase=MET.base;
var LIBC=Process.getModuleByName('libc.so');
function M(o){return mbase.add(o);} function L(n){return LIBC.getExportByName(n);}
var OFF={RDR:0xe2df0,DISP:0x10dc18,BENC:0x159d1c,BDEC:0x15997c,CBCE:0x159de4,CBCD:0x159f58,EINIT:0x159d60};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){try{return p.readByteArray(n);}catch(e){return null;}}
var STORE_DIR='mssdk/ov';
function isStore(p){return p&&(p.indexOf(STORE_DIR)>=0||/\.ms[a-z0-9]*[_.]/.test(p.split('/').pop()));}
var armUntil=0, curStore=null, curCipher=null, events=[], ring=[], RINGMAX=800, fdMap={};
function pushRing(o){ring.push(o); if(ring.length>RINGMAX) ring.shift();}

// crypto primitives: emit when in forward window; always push to ring
function hookBlk(off,name){ Interceptor.attach(M(off),{
  onEnter:function(a){this.i=a[1];this.o=a[2];this.win=(Date.now()<=armUntil);this.st=curStore;},
  onLeave:function(){var IN=b2h(rd(this.i,16)),OUT=b2h(rd(this.o,16));pushRing({ts:Date.now(),name:name,in:IN,out:OUT});
    if(this.win){var ev={t:name,store:this.st,in16:IN,out16:OUT};events.push(ev);
      send({tag:name,store:this.st,in16:IN,out16:OUT});}}
});}
hookBlk(OFF.BENC,'BENC');hookBlk(OFF.BDEC,'BDEC');hookBlk(OFF.CBCE,'CBCE');hookBlk(OFF.CBCD,'CBCD');
Interceptor.attach(M(OFF.DISP),{onEnter:function(a){var m=-1;try{m=a[0].readPointer().readU32();}catch(e){}
  pushRing({ts:Date.now(),name:'DISP',mode:m});
  if(Date.now()<=armUntil){events.push({t:'DISP',store:curStore,mode:m});send({tag:'DISP',store:curStore,mode:m});}}});
Interceptor.attach(M(OFF.EINIT),{onEnter:function(a){var kb=-1;try{kb=a[2].toInt32();}catch(e){}
  var uk=null,iv=null;try{uk=b2h(rd(a[1],kb>0&&kb<=32?kb:16));}catch(e){}try{iv=b2h(rd(a[3],16));}catch(e){}
  var inw=(Date.now()<=armUntil);var ev={t:'EINIT',win:inw,store:inw?curStore:null,kb:kb,key:uk,iv:iv};
  events.push(ev);send({tag:'EINIT',win:inw,store:ev.store,kb:kb,key:uk,iv:iv});}});

// RDR: identify store + ciphertext, arm forward window
Interceptor.attach(M(OFF.RDR),{
  onEnter:function(a){this.pbuf=a[1];this.plen=a[2];try{this.path=a[0].readUtf8String();}catch(e){this.path=null;}},
  onLeave:function(){if(!this.path||!isStore(this.path))return;var name=this.path.split('/').pop();
    var len=0,buf=null;try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
    try{buf=this.pbuf.readPointer();}catch(e){}
    var full=(buf&&len)?b2h(rd(buf,Math.min(len,4096))):null;
    curStore=name;curCipher=full;armUntil=Date.now()+200;
    events.push({t:'RDR',store:name,len:len,cipher:full});
    send({tag:'RDR',store:name,len:len,head:full?full.slice(0,32):null});}
});
// libc read() capture on store fds (belt-and-suspenders vs RDR)
Interceptor.attach(L('openat'),{onEnter:function(a){try{this.p=a[1].readUtf8String();}catch(e){this.p=null;}},
  onLeave:function(r){if(this.p&&isStore(this.p)){var fd=r.toInt32();if(fd>=0){fdMap[fd]=this.p;send({tag:'OPEN',path:this.p.split('/').pop(),fd:fd});}}}});
Interceptor.attach(L('read'),{onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd]){this.fd=fd;this.buf=a[1];}},
  onLeave:function(r){if(this.fd!==undefined){var n=r.toInt32();if(n>0){var h=b2h(rd(this.buf,Math.min(n,4096)));
    events.push({t:'READ',store:fdMap[this.fd].split('/').pop(),n:n,cipher:h});
    send({tag:'READ',store:fdMap[this.fd].split('/').pop(),n:n,head:h?h.slice(0,32):null});}}}});
Interceptor.attach(L('close'),{onEnter:function(a){var fd=a[0].toInt32();if(fdMap[fd])delete fdMap[fd];}});

rpc.exports={dump:function(){return {events:events};},ring:function(){return ring.slice(-60);}};
send({tag:'READY8',mbase:mbase.toString()});
