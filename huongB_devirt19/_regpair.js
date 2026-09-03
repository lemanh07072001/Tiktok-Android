'use strict';
// Capture ALL TT-strings {u32 cap,u32 size,ptr} with their HEADER address, so key/value
// can be paired offline by memory adjacency. Persist-handler 0x12fd3c.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=6000; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function ttstr(A){try{ if(!rok(A))return null;
  var cap=A.readU32(),size=A.add(4).readU32(),data=A.add(8).readPointer();
  if(size===0||size>4096||cap<size||cap>131072)return null; if(!rok(data))return null;
  var b=data.readByteArray(Math.min(size,320)); if(!b)return null;
  var ctx=null; try{ctx=b2h(A.sub(48).readByteArray(256));}catch(e){}
  return {hdr:A.toString(),size:size,hex:b2h(b),ctx:ctx};
}catch(e){return null;}}
function scan(root,depth,budget){ if(depth<0||!rok(root)||budget.n>400)return;
  for(var off=0;off<128;off+=8){ budget.n++; var A=root.add(off);
    var s=ttstr(A); if(s){var k=s.hdr; if(!seen[k]){seen[k]=1; if(log.length<CAP)log.push(s);}}
    if(depth>0){try{var q=A.readPointer(); if(rok(q)&&q.compare(root)!==0)scan(q,depth-1,budget);}catch(e){}}
  }
}
try{ Interceptor.attach(META.add(0x12fd3c),{onEnter:function(){var b={n:0};for(var i=0;i<5;i++){var r=this.context['x'+i];if(rok(r))scan(r,3,b);}}}); send({k:'HOOK'});}catch(e){send({k:'ERR',e:''+e});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
