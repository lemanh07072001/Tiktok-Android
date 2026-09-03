'use strict';
// Hook the blr in the file-WRITE fn (0x12ebfc) — captures the resolved crypt/write target
// (x8) + the plaintext record buffers (x0/x1 TT-strings) about to be encrypted+written.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var BLRW=0x12ebfc, BLRR=0x12ee10; // write-blr; read fn entry (find its blr too)
var log=[]; var CAP=400; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function moff(a){if(!a)return null;if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'M+0x'+a.sub(META).toString(16);var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}
function ttstr(A){try{ if(!rok(A))return null; var cap=A.readU32(),size=A.add(4).readU32(),data=A.add(8).readPointer();
  if(size===0||size>8192||cap<size||cap>131072||!rok(data))return null;
  return {size:size,hex:b2h(data.readByteArray(Math.min(size,400)))};
}catch(e){return null;}}
// hook write blr
try{ Interceptor.attach(META.add(BLRW),{onEnter:function(a){
  var x8=this.context.x8, x0=this.context.x0, x1=this.context.x1, w2=this.context.x2, w3=this.context.x3;
  var d0=ttstr(x0), d1=ttstr(x1);
  var key='W|'+moff(x8)+'|'+(d0?d0.hex.slice(0,32):'');
  if(seen[key])return; seen[key]=1;
  if(log.length<CAP){log.push({kind:'WRITE_BLR',target:moff(x8),w2:w2?w2.toInt32():null,w3:w3?w3.toInt32():null,data0:d0,data1:d1});
    send({k:'W',target:moff(x8)});}
}}); send({k:'HOOKW'}); }catch(e){send({k:'ERRW',e:''+e});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
