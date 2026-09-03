'use strict';
// SPAWN-GATE STORE ORACLE — capture key/IV at STARTUP store decrypt.
// Attach-only, spawn-gated (NOT JDWP). Fresh process = no re-register.
var MOD='libmetasec_ov.so';
var base=null;
function A(o){ return base.add(o); }
var OFF={ RDR:0xe2df0, FOPEN:0x16facc, EINIT:0x159d60, DISP:0x10dc18,
          BENC:0x159d1c, BDEC:0x15997c, CBCD:0x159f58 };
var STORE_RE=/mssdk\/ov|\.ms(s|p|f3|fs|f)?[_.]/;
var log=[]; var armUntil=0; var curPath=null; var seen={};
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;} return s; }
function rN(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
function armIfStore(path){
  if(!path) return false;
  var b=path.split('/').pop();
  if(!STORE_RE.test(path)) return false;
  curPath=path; armUntil=Date.now()+400;
  log.push({t:'OPEN',path:path}); send({tag:'OPEN',path:path});
  return true;
}
function hookReady(){
  base=Process.getModuleByName(MOD).base;
  send({tag:'BASE',base:base.toString()});
  // fopen-wrapper: (x0=path, x1=mode) -> FILE*
  Interceptor.attach(A(OFF.FOPEN),{ onEnter:function(a){ try{armIfStore(a[0].readUtf8String());}catch(e){} }});
  // low-level file reader RDR(x0=path,...)
  Interceptor.attach(A(OFF.RDR),{ onEnter:function(a){ try{armIfStore(a[0].readUtf8String());}catch(e){} }});
  // EINIT(ctx,userKey,keyBytes,iv) — log ALWAYS, tag armed window
  Interceptor.attach(A(OFF.EINIT),{
    onEnter:function(a){
      var kb=-1; try{kb=a[2].toInt32();}catch(e){}
      var n=(kb>0&&kb<=32)?kb:32;
      var key=null,iv=null;
      try{key=b2h(rN(a[1],n));}catch(e){}
      try{iv=b2h(rN(a[3],16));}catch(e){}
      var armed=(Date.now()<=armUntil);
      var k='E|'+key+'|'+iv+'|'+kb;
      if(seen[k]&&!armed) return; seen[k]=1;
      var ev={t:'EINIT',armed:armed,path:armed?curPath:null,keyBytes:kb,key:key,iv:iv};
      log.push(ev);
      if(armed||Object.keys(seen).length<40) send({tag:'EINIT',armed:armed,keyBytes:kb,key:key,iv:iv,path:ev.path});
    }
  });
  // dispatcher: mode selector (in-window only)
  Interceptor.attach(A(OFF.DISP),{
    onEnter:function(a){ if(Date.now()>armUntil)return; var m=-1;try{m=a[0].readPointer().readU32();}catch(e){}
      log.push({t:'DISP',path:curPath,mode:m}); send({tag:'DISP',path:curPath,mode:m}); }
  });
  // decrypt block capture in-window (proves mode + gives pt/ks)
  function hb(off,nm){ Interceptor.attach(A(off),{
    onEnter:function(a){ this.w=(Date.now()<=armUntil); if(!this.w)return; this.i=a[1]; this.o=a[2]; },
    onLeave:function(){ if(!this.w)return; var I=rN(this.i,16),O=rN(this.o,16); var kk=nm+b2h(I); if(seen[kk])return; seen[kk]=1;
      log.push({t:nm,path:curPath,in16:b2h(I),out16:b2h(O)}); send({tag:nm,in16:b2h(I),out16:b2h(O)}); }}); }
  hb(OFF.BDEC,'BDEC'); hb(OFF.BENC,'BENC'); hb(OFF.CBCD,'CBCD');
  send({tag:'HOOKS_ARMED'});
}
// module may not be loaded yet at spawn-gate; poll for it
var iv=setInterval(function(){
  var m=Process.findModuleByName(MOD);
  if(m){ clearInterval(iv); try{hookReady();}catch(e){ send({tag:'ERR',e:''+e}); } }
},20);
rpc.exports={ dump:function(){return log;} };
send({tag:'READY'});
