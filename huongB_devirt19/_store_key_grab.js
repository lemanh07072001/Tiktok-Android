'use strict';
// Path A oracle v3 (Frida 17): DEFER install until libmetasec loads.
// v3 adds: STRM(0x15a598 mode3 stream) + DISP(mode) hooks; EINIT/KSCH dedup by
// (key|kb) so a 90s stable session yields UNIQUE keys, not a firehose. Every
// EINIT/KSCH key is logged regardless of RDR (win flag only TAGS store-window).
var MOD='libmetasec_ov.so';
var OFF={ RDR:0xe2df0, KSCH:0x1591bc, EINIT:0x159d60,
          BENC:0x159d1c, BDEC:0x15997c, CBCE:0x159de4, CBCD:0x159f58,
          STRM:0x15a598, DISP:0x10dc18 };
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var seq=0, armUntil=0, curStore=null, log=[], installed=false, seen={};
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }

function installHooks(base){
  function A(o){ return base.add(o); }
  Interceptor.attach(A(OFF.RDR),{
   onEnter:function(a){ this.pbuf=a[1]; this.plen=a[2]; try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
   onLeave:function(){
     if(!this.path)return; var name=this.path.split('/').pop();
     if(!STORE_RE.test(name))return;
     var len=0,buf=null;
     try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
     try{buf=this.pbuf.readPointer();}catch(e){}
     var full=(buf&&len&&len<8192)?rd(buf,len):null;
     curStore=name; armUntil=Date.now()+150; seq++;
     log.push({t:'RDR',seq:seq,store:name,len:len,cipher:full?b2h(full):null});
     send({tag:'RDR',seq:seq,store:name,len:len});
   }
  });
  Interceptor.attach(A(OFF.KSCH),{
   onEnter:function(a){
     var kb=-1; try{kb=a[2].toInt32();}catch(e){}
     var uk=null; try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){}
     var inWin=(Date.now()<=armUntil);
     var k='K|'+uk+'|'+kb; if(seen[k]&&!inWin)return; seen[k]=1; seq++;
     log.push({t:'KSCH',seq:seq,win:inWin,store:inWin?curStore:null,keyBytes:kb,userKey:uk});
     send({tag:'KSCH',seq:seq,win:inWin,keyBytes:kb,userKey:uk});
   }
  });
  Interceptor.attach(A(OFF.EINIT),{
   onEnter:function(a){
     var kb=-1; try{kb=a[2].toInt32();}catch(e){}
     var uk=null,iv=null;
     try{uk=b2h(rd(a[1],(kb>0&&kb<=32)?kb:16));}catch(e){}
     try{iv=b2h(rd(a[3],16));}catch(e){}
     var inWin=(Date.now()<=armUntil);
     var k='E|'+uk+'|'+iv+'|'+kb; if(seen[k]&&!inWin)return; seen[k]=1; seq++;
     log.push({t:'EINIT',seq:seq,win:inWin,store:inWin?curStore:null,keyBytes:kb,userKey:uk,iv:iv});
     send({tag:'EINIT',seq:seq,win:inWin,keyBytes:kb,userKey:uk,iv:iv});
   }
  });
  Interceptor.attach(A(OFF.DISP),{
   onEnter:function(a){ if(Date.now()>armUntil)return; var mode=-1; try{mode=a[0].readPointer().readU32();}catch(e){}
     seq++; log.push({t:'DISP',seq:seq,store:curStore,mode:mode}); send({tag:'DISP',mode:mode}); }
  });
  function hb(off,nm){ Interceptor.attach(A(off),{
    onEnter:function(a){ this.win=(Date.now()<=armUntil); if(!this.win)return; this.i=a[1]; this.o=a[2]; },
    onLeave:function(){ if(!this.win)return; seq++; log.push({t:nm,seq:seq,store:curStore,in16:b2h(rd(this.i,16)),out16:b2h(rd(this.o,16))}); send({tag:nm,store:curStore}); }
  });}
  hb(OFF.BENC,'BENC'); hb(OFF.BDEC,'BDEC'); hb(OFF.CBCE,'CBCE'); hb(OFF.CBCD,'CBCD'); hb(OFF.STRM,'STRM');
}

function tryInstall(){
  if(installed) return true;
  var base=null;
  try{ Process.enumerateModules().forEach(function(m){ if(m.name===MOD) base=m.base; }); }catch(e){}
  if(!base) return false;
  installed=true; installHooks(base);
  send({tag:'READY',base:base.toString()});
  return true;
}
if(!tryInstall()){
  send({tag:'WAIT_DLOPEN'});
  ['android_dlopen_ext','__loader_android_dlopen_ext','dlopen','__loader_dlopen'].forEach(function(fn){
    var p=Module.findGlobalExportByName?Module.findGlobalExportByName(fn):null; if(!p)return;
    Interceptor.attach(p,{ onLeave:function(){ if(!installed) tryInstall(); } });
  });
}
rpc.exports={ status:function(){return {installed:installed,events:log.length};}, dump:function(){return log;}, clear:function(){log=[];seen={};return true;} };
