'use strict';
// STORE MODE3 ORACLE v9 — fixes vs v8:
//  (1) CRYPT is IN-PLACE (in==out at onLeave). Read PLAIN=in at onEnter (before XOR),
//      CIPHER=out at onLeave. So encrypt: plain@enter -> cipher@leave; decrypt: cipher@enter -> plain@leave.
//  (2) RDR(0xe2df0) reads a store .ms* file -> log path/len/head, ARM 250ms window;
//      any INIT/CRYPT in-window is tagged store=true (isolates store from request firehose).
//  INIT 0x15a598(x0=ctx,x1=userKey,x2=keyBYTES,x3=IV); CRYPT 0x15a628(x0=ctx,x1=in,x2=out,x3=len).
//  KSCH 0x1591bc backup. ATTACH only, delayed. NO re-register.
var MOD='libmetasec_ov.so';
var OFF={INIT:0x15a598, CRYPT:0x15a628, KSCH:0x1591bc, RDR:0xe2df0};
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var log=[], seen={}, ctxKey={}, CAP=1200, MAXBUF=65536;
var armUntil=0, curStore=null, WIN=250;
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
function inWin(){ return Date.now()<=armUntil; }
function install(base){
  function A(o){return base.add(o);}
  // RDR: identify store reads, arm window
  Interceptor.attach(A(OFF.RDR),{
    onEnter:function(a){ this.pbuf=a[1]; this.plen=a[2]; try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(){ if(!this.path)return; var nm=this.path.split('/').pop(); if(!STORE_RE.test(nm))return;
      var len=0,buf=null; try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
      try{buf=this.pbuf.readPointer();}catch(e){}
      var head=(buf&&len)?b2h(rd(buf,Math.min(len,64))):null;
      curStore=nm; armUntil=Date.now()+WIN;
      log.push({t:'RDR',store:nm,len:len,head:head}); send({tag:'RDR',store:nm,len:len,head:head});
    }
  });
  // INIT: key+IV, tag store if in-window
  Interceptor.attach(A(OFF.INIT),{ onEnter:function(a){
    var ctx=a[0].toString(); var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    var key=null,iv=null;
    try{key=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    try{iv=b2h(rd(a[3],16));}catch(e){}
    ctxKey[ctx]={key:key,iv:iv,kb:kb};
    var st=inWin(); var k='I|'+ctx+'|'+key+'|'+iv; if(seen[k]&&!st)return; seen[k]=1;
    log.push({t:'INIT',ctx:ctx,kb:kb,key:key,iv:iv,store:st?curStore:null});
    send({tag:'INIT',key:key,iv:iv,kb:kb,store:st?curStore:null});
  }});
  // CRYPT: read PLAIN=in at onEnter (before in-place XOR), CIPHER=out at onLeave
  Interceptor.attach(A(OFF.CRYPT),{
    onEnter:function(a){ this.ctx=a[0].toString(); this.inp=a[1]; this.outp=a[2];
      try{this.len=a[3].toInt32();}catch(e){this.len=-1;}
      this.win=inWin(); this.store=curStore;
      this.pre=(this.len>0&&this.len<=MAXBUF)? b2h(rd(this.inp,this.len)) : null; },
    onLeave:function(){ if(this.len<0||this.len>MAXBUF)return; if(log.length>=CAP)return;
      var post=b2h(rd(this.outp,this.len));
      var k='C|'+this.ctx+'|'+this.len+'|'+(this.pre?this.pre.slice(0,16):''); if(seen[k]&&!this.win)return; seen[k]=1;
      var kv=ctxKey[this.ctx]||{};
      log.push({t:'CRYPT',ctx:this.ctx,len:this.len,key:kv.key||null,iv:kv.iv||null,pre:this.pre,post:post,store:this.win?this.store:null});
      if(this.win) send({tag:'CRYPT',len:this.len,key:kv.key||null,store:this.store,STORE:true});
    }
  });
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    var uk=null; try{uk=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    var st=inWin(); var k='K|'+uk+'|'+kb; if(seen[k]&&!st)return; seen[k]=1;
    log.push({t:'KSCH',kb:kb,key:uk,store:st?curStore:null}); send({tag:'KSCH',key:uk,store:st?curStore:null});
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
  dump:function(){return log;}, storeonly:function(){return log.filter(function(e){return e.store;});},
  clear:function(){log=[];seen={};ctxKey={};return true;} };
