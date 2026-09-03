'use strict';
// Hook XXTEA core 0x152310(x0=in, x1=len, x2=key16, x3=outlen*) -> ret=out.
// Capture key + input + output for offline reproduce/DIFF. Function hook (tolerated).
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=200; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
try{ Interceptor.attach(META.add(0x152310),{
  onEnter:function(a){
    this.inp=this.context.x0; this.len=this.context.x1.toInt32();
    this.keyp=this.context.x2; this.outlenp=this.context.x3;
    this.key=rok(this.keyp)?b2h(this.keyp.readByteArray(16)):null;
    this.input=(rok(this.inp)&&this.len>0&&this.len<8192)?b2h(this.inp.readByteArray(this.len)):null;
  },
  onLeave:function(r){
    var outlen=-1; try{outlen=this.outlenp.readU32();}catch(e){}
    var out=null; try{if(rok(r)&&outlen>0&&outlen<16384)out=b2h(r.readByteArray(outlen));}catch(e){}
    var k=this.key+'|'+this.input; if(seen[k])return; seen[k]=1;
    if(log.length<CAP){log.push({key:this.key,len:this.len,input:this.input,outlen:outlen,output:out}); send({k:'X',key:this.key,len:this.len});}
  }
}); send({k:'HOOK'}); }catch(e){send({k:'ERR',e:''+e});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
