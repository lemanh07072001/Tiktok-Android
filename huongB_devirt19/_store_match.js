'use strict';
// GROUND-TRUTH-ANCHORED store-crypt finder.
// Capture full in/out of every AES driver/crypt + per-thread last key/IV,
// then post-match byte-exact vs the on-disk store file (same run => same ciphertext).
// ATTACH-ONLY. No re-register.
var MOD='libmetasec_ov.so';
var KSCH=0x1591bc, INIT=0x15a598;              // key schedule + mode3 IV-setter
// candidate crypt entry points (full-buffer or block). We read args generically.
var CRYPTS=[0x15a628,0x15a1dc,0x159d60,0x159618,0x15997c,0x159d1c,0x159de4,0x159f58];
var CAP=4000, MAXBUF=4096;
var log=[]; var seen={}; var lastByT={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){try{return p.readByteArray(n);}catch(e){return null;}}
function isPtr(p){try{return p&&!p.isNull()&&p.compare(ptr(0x1000))>0;}catch(e){return false;}}
function install(base){
  function A(o){return base.add(o);}
  // ---- KSCH: every key, per-thread ----
  Interceptor.attach(A(KSCH),{onEnter:function(a){
    var kb=-1;try{kb=a[2].toInt32();}catch(e){}
    var key=null;try{key=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    var t=Process.getCurrentThreadId(); var e=lastByT[t]||{}; e.key=key; e.kb=kb; lastByT[t]=e;
  }});
  // ---- INIT(mode3): IV + key, per-thread ----
  Interceptor.attach(A(INIT),{onEnter:function(a){
    var kb=-1;try{kb=a[2].toInt32();}catch(e){}
    var key=null;try{key=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
    var iv=null;try{iv=b2h(rd(a[3],16));}catch(e){}
    var t=Process.getCurrentThreadId(); var e=lastByT[t]||{}; if(key)e.key=key; if(kb>0)e.kb=kb; e.iv=iv; lastByT[t]=e;
  }});
  // ---- crypts: capture full in (enter) + out (leave), tag last key/iv ----
  CRYPTS.forEach(function(off){
    Interceptor.attach(A(off),{
      onEnter:function(a){
        if(log.length>=CAP)return;
        this.off=off; this.t=Process.getCurrentThreadId();
        // guess: a1=in, a2=out, a3=len (mode3 CRYPT signature). Fallbacks below.
        this.a1=a[1]; this.a2=a[2];
        var l=-1; try{l=a[3].toInt32();}catch(e){}
        if(!(l>0&&l<=MAXBUF)) l=64;      // block funcs: probe 64B
        this.len=l;
        this.pin = isPtr(this.a1)? b2h(rd(this.a1,Math.min(this.len,MAXBUF))):null;
      },
      onLeave:function(){
        if(log.length>=CAP)return;
        var pout = isPtr(this.a2)? b2h(rd(this.a2,Math.min(this.len,MAXBUF))):null;
        if(!this.pin && !pout) return;
        var k=this.off.toString(16)+'|'+this.len+'|'+(this.pin||'').slice(0,32)+'|'+(pout||'').slice(0,32);
        if(seen[k])return; seen[k]=1;
        var m=lastByT[this.t]||{};
        log.push({off:this.off.toString(16),len:this.len,in:this.pin,out:pout,key:m.key,iv:m.iv,kb:m.kb});
      }
    });
  });
  send({tag:'READY',base:base.toString()});
}
var done=false;
(function(){var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
 if(b){done=true;install(b);return;}
 send({tag:'WAIT'});
 ['android_dlopen_ext','__loader_android_dlopen_ext','dlopen'].forEach(function(fn){
   var p=Module.findGlobalExportByName?Module.findGlobalExportByName(fn):null; if(!p)return;
   Interceptor.attach(p,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){this.p=null;}},
     onLeave:function(){if(done)return;if(this.p&&this.p.indexOf(MOD)>=0){var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});if(b){done=true;install(b);}}}});
 });
})();
rpc.exports={status:function(){return{done:done,n:log.length};},dump:function(){return log;},clear:function(){log=[];seen={};return true;}};
