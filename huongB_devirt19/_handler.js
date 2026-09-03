'use strict';
// Hook the vtable blr at 0x12fa48 to capture concrete store-handler addrs + path,
// then self-expand: hook each new handler, deep-dump buffers (deref 2 levels) to
// catch plaintext<->ciphertext. Function hooks only.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var BLR=0x12fa48;
var log=[]; var CAP=400; var hookedH={}; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rng(p){try{if(!p||p.isNull())return null;return Process.findRangeByAddress(p);}catch(e){return null;}}
function dumpPtr(p,n){var r=rng(p); if(!r||r.protection[0]!=='r')return null; try{return b2h(p.readByteArray(n));}catch(e){return null;}}
function moff(a){ if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'META+0x'+a.sub(META).toString(16); var m=Process.findModuleByAddress(a); return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString(); }
function deepArgs(ctx){
  var out=[];
  for(var i=0;i<6;i++){ var r=ctx['x'+i]; var o={i:i,v:r?r.toString():null};
    var h=dumpPtr(r,64); if(h){ o.hex=h;
      // deref level 2
      try{var p2=r.readPointer(); var h2=dumpPtr(p2,64); if(h2)o.deref=h2;}catch(e){}
      try{var s=r.readCString(64); if(s&&/[ -~]{3,}/.test(s))o.str=s;}catch(e){} }
    out.push(o); }
  return out;
}
function hookHandler(addr){ var key=addr.toString(); if(hookedH[key])return; hookedH[key]=1;
  try{ Interceptor.attach(addr,{
    onEnter:function(a){ this.pre=deepArgs(this.context); this.ctx=this.context; },
    onLeave:function(r){ var post=deepArgs(this.ctx);
      var k=key+'|'+(this.pre[2]?this.pre[2].v:''); if(seen[k])return; seen[k]=1;
      if(log.length<CAP){log.push({handler:moff(addr), ret:r?r.toString():null, pre:this.pre, post:post}); send({k:'HANDLER_HIT',handler:moff(addr)});}
    }
  }); send({k:'HANDLER_HOOKED',handler:moff(addr)}); }catch(e){ send({k:'HHERR',e:''+e}); }
}
if(META){
  Interceptor.attach(META.add(BLR),{
    onEnter:function(a){
      var x8=this.context.x8; var x2=this.context.x2;
      var path=null; try{path=x2.readCString(80);}catch(e){}
      var handler=x8;
      if(log.length<CAP){ log.push({k:'BLR',handler:moff(handler),x8:handler.toString(),path:path}); send({k:'BLR',handler:moff(handler),path:path}); }
      // self-expand: hook this concrete handler
      if(handler&&!handler.isNull()){ hookHandler(handler); }
    }
  });
  send({k:'READY',meta:META.toString()});
}
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length,handlers:Object.keys(hookedH).length};}};
