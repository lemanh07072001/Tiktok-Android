'use strict';
// Hook the 3 crypt CALL-SITES inside store-write fn 0x1182e0 (isolates store from
// request-signing). Capture x20 (input plaintext value) + x0/x1 (output) + the final write.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=800; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function tt(p){try{if(!rok(p))return null;var cap=p.readU32(),size=p.add(4).readU32(),data=p.add(8).readPointer();
  if(size>0&&size<32768&&cap>=size&&rok(data))return {sz:size,hex:b2h(data.readByteArray(Math.min(size,800)))};}catch(e){}return null;}
// call-site hooks: onEnter capture x20(input), x0/x1(out bufs); onLeave re-read x0/x1(filled)
function site(off,kind){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){this.x20=this.context.x20;this.x0=this.context.x0;this.x1=this.context.x1;
    this.inp=tt(this.x20);},
  onLeave:function(r){var o0=tt(this.x0),o1=tt(this.x1);
    var k=kind+'|'+((this.inp&&this.inp.hex)||'');if(seen[k])return;seen[k]=1;
    if(log.length<CAP){log.push({kind:kind,input:this.inp,out0:o0,out1:o1});send({k:kind});}}
}); send({k:'H',s:kind}); }catch(e){send({k:'E',s:kind,e:''+e});} }
site(0x1184a4,'K0'); site(0x1184c8,'XXTEA'); site(0x118500,'K1');
// also capture the final write (path+ciphertext) to pair
try{ Interceptor.attach(META.add(0x118560),{onEnter:function(a){
  var path=tt(this.context.x0), data=tt(this.context.x1);
  if(log.length<CAP)log.push({kind:'WRITE',path:path,data:data});}
}); }catch(e){}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
