'use strict';
// Locate the store-manager via the path-builder (0x1509c0 "%s/%s%s") and reader (0xe2df0).
// Function hooks only (attach-tolerated). Backtrace store-path construction -> caller chain.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var OFF={PB:0x1509c0, RDR:0xe2df0, SHA1:0x10b13c};
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]|msdata|mssdk/;
var log=[]; var CAP=400;
function rdstr(p){try{return p.readUtf8String();}catch(e){return null;}}
function bt(ctx){try{return Thread.backtrace(ctx,Backtracer.ACCURATE).map(function(a){
  if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'META+0x'+a.sub(META).toString(16);
  var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}).slice(0,18);}catch(e){return null;}}
function push(o){if(log.length<CAP){log.push(o);send(o);}}
if(META){
  // path builder: read output at onLeave, check for store path
  Interceptor.attach(META.add(OFF.PB),{
    onEnter:function(a){this.out=a[0]; this.fmt=rdstr(a[1]); this.a2=rdstr(a[2]); this.a3=rdstr(a[3]); this.a4=rdstr(a[4]); this.ctx=this.context;},
    onLeave:function(){ var s=rdstr(this.out); var probe=(s||'')+'|'+(this.a2||'')+'|'+(this.a3||'')+'|'+(this.a4||'');
      if(STORE_RE.test(probe)){ push({k:'PB', out:s, fmt:this.fmt, args:[this.a2,this.a3,this.a4], bt:bt(this.ctx)}); } }
  });
  // reader: path arg
  Interceptor.attach(META.add(OFF.RDR),{
    onEnter:function(a){ this.path=rdstr(a[0]); this.p1=a[1]; this.p2=a[2]; this.ctx=this.context; },
    onLeave:function(r){ if(this.path&&STORE_RE.test(this.path)){ var len=0,buf=null,head=null;
      try{len=this.p2.readU64().toNumber();}catch(e){try{len=this.p2.readU32();}catch(e2){}}
      try{buf=this.p1.readPointer();}catch(e){}
      try{if(buf&&len)head=buf.readByteArray(Math.min(len,64));}catch(e){}
      function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
      push({k:'RDR', path:this.path.split('/').pop(), len:len, head:b2h(head), bt:bt(this.ctx)}); } }
  });
}
send({k:'READY',meta:META?META.toString():null});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
