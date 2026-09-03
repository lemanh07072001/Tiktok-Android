'use strict';
// (B) Catch the persist WRITE: hook persist handler 0x12fd3c (+ dispatcher blr 0x12fa48)
// capture RAW buffers (no printability filter) following std::string/vector data ptrs,
// so binary plaintext is not missed. Match vs on-disk ct offline. Function hooks (tolerated).
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var PERSIST=[0x12fd3c,0x13accc];  // all candidate handlers
var BLR=0x12fa48;
var log=[]; var CAP=800; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function moff(a){if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'M+0x'+a.sub(META).toString(16);var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}
function grab(p,depth,acc,tag,budget){
  if(depth<0||!rok(p)||budget.n>40)return;
  var hx=null; try{hx=b2h(p.readByteArray(256));}catch(e){return;} if(!hx)return;
  budget.n++;
  acc.push({t:tag,a:p.toString(),hex:hx});
  for(var off=0;off<64;off+=8){ try{var q=p.add(off).readPointer(); if(rok(q)) grab(q,depth-1,acc,tag+'+'+off+'>',budget);}catch(e){} }
}
function snap(ctx){ var acc=[]; var b={n:0}; for(var i=0;i<5;i++){var r=ctx['x'+i]; if(rok(r)) grab(r,1,acc,'x'+i,b);} return acc; }
PERSIST.forEach(function(off){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){this.off=off;this.ctx=this.context;this.pre=snap(this.context);this.bt=(function(){try{return Thread.backtrace(this.context,Backtracer.ACCURATE).map(moff).slice(0,6);}catch(e){return null;}}).call(this);},
  onLeave:function(r){var post=snap(this.ctx);
    var key=off+'|'+(this.pre[0]?this.pre[0].hex.slice(0,24):'');
    if(seen[key])return;seen[key]=1;
    if(log.length<CAP)log.push({fn:'0x'+off.toString(16),ret:r?r.toString():null,bt:this.bt,pre:this.pre,post:post});
  }}); send({k:'HOOK',off:'0x'+off.toString(16)}); }catch(e){send({k:'ERR',off:'0x'+off.toString(16),e:''+e});} });
// dispatcher blr: log which handler fires (esp. for writes)
try{ Interceptor.attach(META.add(BLR),{onEnter:function(a){var x8=this.context.x8;if(log.length<CAP)log.push({fn:'BLR',handler:moff(x8)});}}); }catch(e){}
send({k:'READY'});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
