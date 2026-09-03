'use strict';
// Extract TT-strings {u32 cap, u32 size, char* data} from the settings registry
// reachable from persist-handler args. Collect all strings + their container addr.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var HANDLERS=[0x12fd3c];
var log=[]; var CAP=2000; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
// try parse a TT-string header at A: {cap:u32@0, size:u32@4, data:ptr@8}
function ttstr(A){ try{
  if(!rok(A))return null;
  var cap=A.readU32(); var size=A.add(4).readU32(); var data=A.add(8).readPointer();
  if(size===0||size>8192||cap<size||cap>65536) return null;
  if(!rok(data)) return null;
  var n=Math.min(size,600);
  var bytes=data.readByteArray(n); if(!bytes)return null;
  return {cap:cap,size:size,data:data.toString(),hex:b2h(bytes)};
}catch(e){return null;} }
function scan(root,depth,acc,budget){
  if(depth<0||!rok(root)||budget.n>400)return;
  // try string header at root and at each 8-byte slot
  for(var off=0; off<128; off+=8){ budget.n++;
    var A=root.add(off);
    var s=ttstr(A);
    if(s){ var k=s.data+'|'+s.size; if(!seen[k]){seen[k]=1; if(log.length<CAP)log.push(s);} }
    // recurse into pointer at this slot
    if(depth>0){ try{var q=A.readPointer(); if(rok(q)&&q.compare(root)!==0) scan(q,depth-1,acc,budget);}catch(e){} }
  }
}
HANDLERS.forEach(function(off){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){ var b={n:0}; for(var i=0;i<5;i++){var r=this.context['x'+i]; if(rok(r)) scan(r,3,null,b);} }
}); send({k:'HOOK',off:'0x'+off.toString(16)}); }catch(e){send({k:'ERR',e:''+e});} });
send({k:'READY'});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
