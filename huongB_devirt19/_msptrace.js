'use strict';
// .msp container tracer (stable env): crypt-wrapper 0x10dce0 (value in/out) +
// store-op 0x11a64c + write 0x12e79c (final .msp bytes). Full-buffer capture.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var log=[]; var CAP=1500; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function tt(p){try{if(!rok(p))return null;var cap=p.readU32(),size=p.add(4).readU32(),data=p.add(8).readPointer();
  if(size>0&&size<16384&&cap>=size&&rok(data))return {sz:size,hex:b2h(data.readByteArray(Math.min(size,600)))};}catch(e){}return null;}
function push(o){var k=o.k+'|'+(o.sig||'');if(seen[k])return;seen[k]=1;if(log.length<CAP){log.push(o);send({k:o.k});}}
// 0x10dce0(x0=ctx, x1=value) -> transform; capture x0,x1 tt + result at [x8]
try{ Interceptor.attach(META.add(0x10dce0),{
  onEnter:function(a){this.x0=this.context.x0;this.x1=this.context.x1;this.x8=this.context.x8;
    this.in0=tt(this.x0);this.in1=tt(this.x1);},
  onLeave:function(r){var out=this.x8&&rok(this.x8)?tt(this.x8):null;
    push({k:'DCE0',in0:this.in0,in1:this.in1,out:out,sig:(this.in1&&this.in1.hex||'')+(this.in0&&this.in0.hex||'').slice(0,16)});}
}); }catch(e){}
// 0x11a64c(w0,w1,x2,x3,x4) store op
try{ Interceptor.attach(META.add(0x11a64c),{onEnter:function(a){
  push({k:'STORE',w0:this.context.x0.toInt32(),x3:tt(this.context.x3),x4:tt(this.context.x4),sig:''+this.context.x0});}
}); }catch(e){}
// 0x12e79c(x0=path,x1=data) fwrite
try{ Interceptor.attach(META.add(0x12e79c),{onEnter:function(a){
  var p=tt(this.context.x0), d=tt(this.context.x1);
  var fn=null; try{fn=(p&&p.hex)?String.fromCharCode.apply(null,new Uint8Array(this.context.x0.add(8).readPointer().readByteArray(120))).split('/').pop():null;}catch(e){}
  push({k:'WRITE',file:fn,path:p,data:d,sig:(d&&d.hex||'').slice(0,32)});}
}); }catch(e){}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
