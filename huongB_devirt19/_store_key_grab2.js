'use strict';
// STORE ORACLE v3 — installs at dlopen-time so hooks are live BEFORE libmetasec's
// JNI init reads the store (v2 lost that race with a 40ms poll). Adds a debug RDR
// that logs ANY path under ov/ | mssdk | .ms* to confirm the reader + catch the read.
var MOD='libmetasec_ov.so';
var OFF={RDR:0xe2df0,KSCH:0x1591bc,EINIT:0x159d60,BENC:0x159d1c,BDEC:0x15997c,CBCE:0x159de4,CBCD:0x159f58};
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var DBG_RE=/(mssdk|\/ov\/|\.msdata|\.ms[a-z0-9]*_)/i;
var seq=0, armUntil=0, curStore=null, log=[], installed=false;

function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }

function installHooks(base){
  function A(o){ return base.add(o); }
  Interceptor.attach(A(OFF.RDR),{
   onEnter:function(a){ this.pbuf=a[1]; this.plen=a[2]; try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
   onLeave:function(){
     if(!this.path)return; var name=this.path.split('/').pop();
     var isStore=STORE_RE.test(name), isDbg=DBG_RE.test(this.path);
     if(!isStore && !isDbg) return;
     var len=0,buf=null;
     try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
     try{buf=this.pbuf.readPointer();}catch(e){}
     var full=(buf&&len&&len<8192)?rd(buf,len):null;
     if(isStore){ curStore=name; armUntil=Date.now()+200; }
     seq++;
     log.push({t:'RDR',seq:seq,store:isStore?name:null,path:this.path,len:len,cipher:full?b2h(full):null});
     send({tag:'RDR',seq:seq,store:isStore?name:null,path:this.path,len:len});
   }
  });
  Interceptor.attach(A(OFF.KSCH),{
   onEnter:function(a){
     var kb=-1; try{kb=a[2].toInt32();}catch(e){}
     var uk=null; try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){}
     var inWin=(Date.now()<=armUntil); seq++;
     log.push({t:'KSCH',seq:seq,win:inWin,store:inWin?curStore:null,keyBytes:kb,userKey:uk});
     send({tag:'KSCH',seq:seq,win:inWin,keyBytes:kb});
   }
  });
  Interceptor.attach(A(OFF.EINIT),{
   onEnter:function(a){
     var kb=-1; try{kb=a[2].toInt32();}catch(e){}
     var uk=null,iv=null;
     try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){}
     try{iv=b2h(rd(a[3],16));}catch(e){}
     var inWin=(Date.now()<=armUntil); seq++;
     log.push({t:'EINIT',seq:seq,win:inWin,store:inWin?curStore:null,keyBytes:kb,userKey:uk,iv:iv});
     send({tag:'EINIT',seq:seq,win:inWin,keyBytes:kb});
   }
  });
  function hb(off,nm){ Interceptor.attach(A(off),{
    onEnter:function(a){ this.win=(Date.now()<=armUntil); if(!this.win)return; this.i=a[1]; this.o=a[2]; },
    onLeave:function(){ if(!this.win)return; seq++; log.push({t:nm,seq:seq,store:curStore,in16:b2h(rd(this.i,16)),out16:b2h(rd(this.o,16))}); }
  });}
  hb(OFF.BENC,'BENC'); hb(OFF.BDEC,'BDEC'); hb(OFF.CBCE,'CBCE'); hb(OFF.CBCD,'CBCD');
}

function findBase(){ var b=null; try{Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});}catch(e){} return b; }
function tryInstall(){ if(installed)return true; var b=findBase(); if(!b)return false; installed=true; installHooks(b); send({tag:'READY',base:b.toString()}); return true; }

// resolve an export across Frida 17 API variants
function resolveExport(name){
  try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(name); }catch(e){}
  try{ if(Module.findGlobalExportByName){ var p=Module.findGlobalExportByName(name); if(p)return p; } }catch(e){}
  var r=null;
  try{ Process.enumerateModules().forEach(function(m){ if(r)return; try{ var e=(m.findExportByName?m.findExportByName(name):null); if(e)r=e; }catch(_){} }); }catch(e){}
  return r;
}
// hook dlopen variants so we install the INSTANT libmetasec maps (pre-JNI-init)
['android_dlopen_ext','__loader_android_dlopen_ext','dlopen'].forEach(function(fn){
  var p=resolveExport(fn); if(!p) return;
  try{ Interceptor.attach(p,{ onLeave:function(){ if(!installed) tryInstall(); } }); }catch(e){}
});

rpc.exports={ dump:function(){return log;}, status:function(){return {installed:installed,events:log.length};} };
if(!tryInstall()){ var iv=setInterval(function(){ if(tryInstall()) clearInterval(iv); }, 20); }
send({tag:'BOOT',msg:'oracle v3 armed (dlopen-early), waiting for '+MOD});
