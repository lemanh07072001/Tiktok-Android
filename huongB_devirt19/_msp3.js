'use strict';
// The 3 store crypts (mod-3 dispatch @0x118480): 0x10dce0(XXTEA,.msf3),
// 0x10c158(kind1), 0x10bbd0(kind0,.msp device-secret). Capture in(x1)/out.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=1500; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function tt(p){try{if(!rok(p))return null;var cap=p.readU32(),size=p.add(4).readU32(),data=p.add(8).readPointer();
  if(size>0&&size<32768&&cap>=size&&rok(data))return {sz:size,hex:b2h(data.readByteArray(Math.min(size,700)))};}catch(e){}return null;}
function hookC(off,tag){ try{ Interceptor.attach(META.add(off),{
  onEnter:function(a){this.x0=this.context.x0;this.x1=this.context.x1;this.x2=this.context.x2;
    this.in0=tt(this.x0);this.in1=tt(this.x1);this.o2=this.x2;},
  onLeave:function(r){var out0=tt(this.x0), out2=(this.o2&&rok(this.o2))?tt(this.o2):null;
    var k=tag+'|'+((this.in1&&this.in1.hex)||'')+'|'+((this.in0&&this.in0.hex)||'');if(seen[k])return;seen[k]=1;
    if(log.length<CAP){log.push({fn:tag,in0:this.in0,in1:this.in1,out0:out0,out2:out2});send({k:tag});}}
}); send({k:'H',tag:tag}); }catch(e){send({k:'E',tag:tag,e:''+e});} }
hookC(0x10dce0,'XXTEA'); hookC(0x10c158,'K1'); hookC(0x10bbd0,'K0');
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
