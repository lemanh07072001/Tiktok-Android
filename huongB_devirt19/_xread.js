'use strict';
// Hook ALL XXTEA fns: enc 0x152310, DEC 0x1525f8 (read path), 2nd 0x146318.
// Capture (fn, key, in, out) — DEC onLeave = decrypted device-secret plaintext.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=4000; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function hookXX(off,tag){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){this.inp=this.context.x0;this.len=this.context.x1.toInt32();this.keyp=this.context.x2;this.olp=this.context.x3;
    this.key=rok(this.keyp)?b2h(this.keyp.readByteArray(16)):null;
    this.input=(rok(this.inp)&&this.len>0&&this.len<16384)?b2h(this.inp.readByteArray(this.len)):null;},
  onLeave:function(r){var ol=-1;try{ol=this.olp.readU32();}catch(e){}var out=null;try{if(rok(r)&&ol>0&&ol<32768)out=b2h(r.readByteArray(ol));}catch(e){}
    var k=tag+'|'+this.key+'|'+this.input+'|'+out;if(seen[k])return;seen[k]=1;
    if(log.length<CAP)log.push({fn:tag,key:this.key,inlen:this.len,input:this.input,outlen:ol,output:out});}
}); send({k:'H',tag:tag}); }catch(e){send({k:'E',tag:tag,e:''+e});} }
hookXX(0x152310,'ENC'); hookXX(0x1525f8,'DEC'); hookXX(0x146318,'XX2');
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
