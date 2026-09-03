'use strict';
// End-to-end: hook XXTEA core 0x152310 (key,in,out) + file-write 0x12e79c (path,data).
// Pair by output==data => (path, key, plaintext, ciphertext) for on-disk DIFF.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=400; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function ttstr(A){try{if(!rok(A))return null;var cap=A.readU32(),size=A.add(4).readU32(),data=A.add(8).readPointer();
  if(size===0||size>8192||cap<size||!rok(data))return null;return {size:size,hex:b2h(data.readByteArray(Math.min(size,600)))};}catch(e){return null;}}
// XXTEA 0x152310(x0=in,x1=len,x2=key,x3=&outlen)->ret
try{ Interceptor.attach(META.add(0x152310),{
  onEnter:function(a){this.inp=this.context.x0;this.len=this.context.x1.toInt32();this.keyp=this.context.x2;this.olp=this.context.x3;
    this.key=rok(this.keyp)?b2h(this.keyp.readByteArray(16)):null;
    this.input=(rok(this.inp)&&this.len>0&&this.len<8192)?b2h(this.inp.readByteArray(this.len)):null;},
  onLeave:function(r){var ol=-1;try{ol=this.olp.readU32();}catch(e){}var out=null;try{if(rok(r)&&ol>0&&ol<16384)out=b2h(r.readByteArray(ol));}catch(e){}
    var k='X|'+this.key+'|'+this.input;if(seen[k])return;seen[k]=1;
    if(log.length<CAP)log.push({t:'X',key:this.key,input:this.input,output:out});}
}); send({k:'HOOKX'});}catch(e){send({k:'ERR',e:''+e});}
// write 0x12e79c(x0=path,x1=data)
try{ Interceptor.attach(META.add(0x12e79c),{
  onEnter:function(a){var path=ttstr(this.context.x0),data=ttstr(this.context.x1);
    if(!path||!data)return;var k='W|'+path.hex+'|'+data.hex;if(seen[k])return;seen[k]=1;
    if(log.length<CAP)log.push({t:'W',path:path.hex,data:data.hex});}
}); send({k:'HOOKW'});}catch(e){send({k:'ERRW',e:''+e});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
