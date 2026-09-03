'use strict';
// WRITE-PATH v2: filter by store DIRECTORY (catches tmpfile+rename), backtrace
// each store write into libmetasec to reveal the crypt caller. ATTACH-ONLY.
var DIR_RE=/msdata|mssdk\/ov|\/ov\//;           // store directory, not filename
var MOD='libmetasec_ov.so';
var log=[]; var fdpath={}; var META=null, MSIZE=0;
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function gx(n){try{return Module.findGlobalExportByName(n);}catch(e){return null;}}
function findMeta(){Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});}
findMeta();
function bt(ctx){
  try{return Thread.backtrace(ctx,Backtracer.ACCURATE).map(function(a){
    if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0) return 'META+0x'+a.sub(META).toString(16);
    var m=Process.findModuleByAddress(a); return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();
  }).slice(0,12);}catch(e){return null;}
}
var HOOK=[],MISS=[];
function hookOpen(name,pathIdx){var p=gx(name);if(!p){MISS.push(name);return;}
  Interceptor.attach(p,{onEnter:function(a){try{this.path=a[pathIdx].readUtf8String();}catch(e){this.path=null;}},
    onLeave:function(r){if(!this.path)return;if(!DIR_RE.test(this.path))return;var fd=r.toInt32();if(fd>=0)fdpath[fd]=this.path;
      log.push({k:'OPEN',fn:name,fd:fd,path:this.path});send({k:'OPEN',fn:name,fd:fd,path:this.path});}});HOOK.push(name);}
hookOpen('open',0);hookOpen('open64',0);hookOpen('openat',1);hookOpen('openat64',1);hookOpen('__openat',1);hookOpen('creat',0);

function hookWrite(name,fdIdx,bufIdx,lenIdx){var p=gx(name);if(!p){MISS.push(name);return;}
  Interceptor.attach(p,{onEnter:function(a){var fd=a[fdIdx].toInt32();var path=fdpath[fd];if(!path)return;
    var len=0;try{len=a[lenIdx].toInt32();}catch(e){}var head=null;try{head=b2h(a[bufIdx].readByteArray(Math.min(len>0?len:64,256)));}catch(e){}
    var b=bt(this.context);
    log.push({k:'WRITE',fn:name,fd:fd,path:path,len:len,head:head,bt:b});send({k:'WRITE',fn:name,path:path,len:len,head:head?head.slice(0,64):null,bt:b?b.slice(0,6):null});}});HOOK.push(name);}
hookWrite('write',0,1,2);hookWrite('pwrite64',0,1,2);hookWrite('__write_chk',0,1,2);
(function(){var p=gx('writev');if(!p){MISS.push('writev');return;}
 Interceptor.attach(p,{onEnter:function(a){var fd=a[0].toInt32();var path=fdpath[fd];if(!path)return;
   var iov=a[1],head=null,len=0;try{var base=iov.readPointer();len=iov.add(Process.pointerSize).readU64().toNumber();head=b2h(base.readByteArray(Math.min(len,256)));}catch(e){}
   var b=bt(this.context);log.push({k:'WRITEV',path:path,len:len,head:head,bt:b});send({k:'WRITEV',path:path,len:len,head:head?head.slice(0,64):null,bt:b?b.slice(0,6):null});}});HOOK.push('writev');})();

function hookRename(name,aIdx,bIdx){var p=gx(name);if(!p){MISS.push(name);return;}
  Interceptor.attach(p,{onEnter:function(a){var f=null,t=null;try{f=a[aIdx].readUtf8String();}catch(e){}try{t=a[bIdx].readUtf8String();}catch(e){}
    if((f&&DIR_RE.test(f))||(t&&DIR_RE.test(t))){log.push({k:'RENAME',from:f,to:t});send({k:'RENAME',from:f,to:t});}}});HOOK.push(name);}
hookRename('rename',0,1);hookRename('renameat',1,3);

send({k:'READY',meta:META?META.toString():null,hooked:HOOK,miss:MISS});
rpc.exports={status:function(){return{n:log.length};},dump:function(){return log;},clear:function(){log=[];fdpath={};return true;}};
