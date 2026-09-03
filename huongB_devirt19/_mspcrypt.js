'use strict';
// Resolve .msp crypt via indirect blr: 0x138ccc (sdi_v2 handler) + 0x13c3e4 (entry-encoder).
// Capture resolved target x8 + arg buffers (device-secret plaintext).
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var log=[]; var CAP=800; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function moff(a){if(!a)return null;if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'M+0x'+a.sub(META).toString(16);var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}
function grab(p){ if(!rok(p))return null; var o={v:p.toString()};
  try{o.raw=b2h(p.readByteArray(64));}catch(e){}
  // TT-string {cap,size,ptr}
  try{var cap=p.readU32(),size=p.add(4).readU32(),data=p.add(8).readPointer();
    if(size>0&&size<8192&&cap>=size&&rok(data))o.tt=b2h(data.readByteArray(Math.min(size,400)));}catch(e){}
  // deref
  try{var q=p.readPointer(); if(rok(q))o.deref=b2h(q.readByteArray(64));}catch(e){}
  return o; }
function hookBlr(off,tag){ try{ Interceptor.attach(META.add(off),{onEnter:function(a){
  var x8=this.context.x8, ctx=this.context;
  var e={tag:tag, target:moff(x8), x0:grab(ctx.x0), x1:grab(ctx.x1), x2:grab(ctx.x2)};
  var k=tag+'|'+e.target+'|'+((e.x1&&e.x1.tt)||(e.x0&&e.x0.tt)||'');
  if(seen[k])return; seen[k]=1;
  if(log.length<CAP){log.push(e); send({k:'B',tag:tag,target:e.target});}
}}); send({k:'H',tag:tag}); }catch(e){send({k:'E',tag:tag,e:''+e});} }
hookBlr(0x138ccc,'SDIV2'); hookBlr(0x13c3e4,'ENCODE');
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
