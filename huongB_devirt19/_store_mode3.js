'use strict';
// STORE MODE3 ORACLE v8 — CORRECT init/crypt offsets from static disasm.
//   INIT  0x15a598: mode3_init(x0=ctx, x1=userKey, x2=keyBYTES, x3=IV)  -> maps ctx->{key,iv}
//   CRYPT 0x15a628: mode3_crypt(x0=ctx, x1=in, x2=out, x3=len)  out=in^keystream
//   KSCH  0x1591bc: backup key capture.
// mode3 == store stream (length-preserving). On launch the store is RE-WRITTEN,
// so CRYPT on the ENCRYPT path gives in=PLAINTEXT directly (no key brute needed).
// Light: buffers read onLeave only, deduped, capped -> no ANR. ATTACH or SPAWN. NO re-register.
var MOD='libmetasec_ov.so';
var OFF={INIT:0x15a598, CRYPT:0x15a628, KSCH:0x1591bc};
var log=[], seen={}, ctxKey={}, CAP=400, MAXBUF=16384;
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
function install(base){
  function A(o){return base.add(o);}
  Interceptor.attach(A(OFF.INIT),{ onEnter:function(a){
    var ctx=a[0].toString(); var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    var key=null,iv=null;
    try{key=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    try{iv=b2h(rd(a[3],16));}catch(e){}
    ctxKey[ctx]={key:key,iv:iv,kb:kb};
    var k='I|'+ctx+'|'+key+'|'+iv; if(seen[k])return; seen[k]=1;
    log.push({t:'INIT',ctx:ctx,kb:kb,key:key,iv:iv}); send({tag:'INIT',key:key,iv:iv,kb:kb});
  }});
  Interceptor.attach(A(OFF.CRYPT),{
    onEnter:function(a){ this.ctx=a[0].toString(); this.inp=a[1]; this.outp=a[2];
      try{this.len=a[3].toInt32();}catch(e){this.len=-1;} },
    onLeave:function(){ if(this.len<0||this.len>MAXBUF)return; if(log.length>=CAP)return;
      var IN=b2h(rd(this.inp,this.len)), OUT=b2h(rd(this.outp,this.len));
      var k='C|'+this.ctx+'|'+this.len+'|'+(IN?IN.slice(0,16):''); if(seen[k])return; seen[k]=1;
      var kv=ctxKey[this.ctx]||{}; 
      log.push({t:'CRYPT',ctx:this.ctx,len:this.len,key:kv.key||null,iv:kv.iv||null,in:IN,out:OUT});
      send({tag:'CRYPT',len:this.len,key:kv.key||null});
    }
  });
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    var uk=null; try{uk=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    var k='K|'+uk+'|'+kb; if(seen[k])return; seen[k]=1;
    log.push({t:'KSCH',kb:kb,key:uk}); send({tag:'KSCH',key:uk});
  }});
  send({tag:'READY',base:base.toString()});
}
var done=false;
function tryPreload(){ var b=null; Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
  if(b){done=true; install(b); return true;} return false; }
if(!tryPreload()){
  send({tag:'WAIT_DLOPEN'});
  ['android_dlopen_ext','__loader_android_dlopen_ext','dlopen','__loader_dlopen'].forEach(function(fn){
    var p=Module.findGlobalExportByName?Module.findGlobalExportByName(fn):null; if(!p)return;
    Interceptor.attach(p,{ onEnter:function(a){try{this.path=a[0].readUtf8String();}catch(e){this.path=null;}},
      onLeave:function(){ if(done)return; if(this.path&&this.path.indexOf(MOD)>=0){
        var b=null; Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
        if(b){done=true; install(b);} } } });
  });
}
rpc.exports={ status:function(){return {done:done,events:log.length};},
  dump:function(){return log;}, clear:function(){log=[];seen={};ctxKey={};return true;} };
