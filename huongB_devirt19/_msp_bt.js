'use strict';
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var log=[]; var CAP=60; var seen={};
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function ttstr(A){try{if(!rok(A))return null;var cap=A.readU32(),size=A.add(4).readU32(),data=A.add(8).readPointer();
  if(size===0||size>8192||cap<size||!rok(data))return null;return data.readCString(Math.min(size,200));}catch(e){return null;}}
function moff(a){if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'M+0x'+a.sub(META).toString(16);var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}
try{ Interceptor.attach(META.add(0x12e79c),{onEnter:function(a){
  var p=ttstr(this.context.x0); if(!p)return;
  var fn=p.split('/').pop();
  var isMsp=(fn.indexOf('.msp')===0||fn.indexOf('.mss')===0);
  var tag=isMsp?'MSP':'MSF';
  var key=tag+'|'+fn; if(seen[key])return; seen[key]=1;
  var bt=[]; try{bt=Thread.backtrace(this.context,Backtracer.ACCURATE).map(moff).slice(0,16);}catch(e){}
  if(log.length<CAP){log.push({tag:tag,file:fn,bt:bt}); send({k:tag,file:fn});}
}}); send({k:'HOOK'});}catch(e){send({k:'ERR',e:''+e});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
