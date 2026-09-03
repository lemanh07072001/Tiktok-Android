'use strict';
// Hook the file-I/O cluster (contains inlined svc read/write). Their buffer arg = the
// store ciphertext. Dump args (deref) + backtrace; match vs on-disk. Function hooks (tolerated).
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var FNS=[0xe0d9c,0xe1070,0xe11d0,0xe2df0,0xe0610,0xe0674];
var log=[]; var CAP=600; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function moff(a){if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'META+0x'+a.sub(META).toString(16);var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}
function bt(ctx){try{return Thread.backtrace(ctx,Backtracer.ACCURATE).map(moff).slice(0,8);}catch(e){return null;}}
function args(ctx){var o=[];for(var i=0;i<6;i++){var r=ctx['x'+i];var e={i:i,v:r?r.toString():null};
  if(rok(r)){try{e.hex=b2h(r.readByteArray(80));}catch(x){}
    try{var p2=r.readPointer();if(rok(p2)){e.deref=b2h(p2.readByteArray(80));}}catch(x){}
    try{var s=r.readCString(64);if(s&&/[ -~]{4,}/.test(s))e.str=s;}catch(x){}}
  o.push(e);} return o;}
FNS.forEach(function(off){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){this.off=off;this.ctx=this.context;this.pre=args(this.context);this.bt=bt(this.context);},
  onLeave:function(r){var post=args(this.ctx);
    var key=off+'|'+(this.pre[1]?this.pre[1].v:'')+'|'+(this.pre[2]?this.pre[2].v:'');
    if(seen[key])return;seen[key]=1;
    if(log.length<CAP)log.push({fn:'0x'+off.toString(16),ret:r?r.toString():null,pre:this.pre,post:post,bt:this.bt});
  }}); send({k:'HOOK',off:'0x'+off.toString(16)}); }catch(e){send({k:'ERR',off:'0x'+off.toString(16),e:''+e});} });
send({k:'READY'});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
