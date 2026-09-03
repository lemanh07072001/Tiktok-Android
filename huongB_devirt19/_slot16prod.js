'use strict';
// Hook slot16 PRF 0x879d8 (sel 0x171) + SM3 producer 0xa0748. Capture ctx (x0/x2/x3) +
// SM3 input-message + output slot16. Determine offline message construction. spawn-gate.
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=300; var seen={}; var done=false;
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function dump(p,n){return rok(p)?b2h(p.readByteArray(n)):null;}
function deref(p,n){try{var q=p.readPointer();return rok(q)?b2h(q.readByteArray(n)):null;}catch(e){return null;}}
function install(base){
  // PRF 0x879d8: ctx read
  Interceptor.attach(base.add(0x879d8),{
    onEnter:function(a){this.sel=this.context.x1?this.context.x1.toInt32():-1;
      this.x0=this.context.x0;this.x2=this.context.x2;this.x3=this.context.x3;this.x4=this.context.x4;
      this.pre={x0:dump(this.x0,64),x0d:deref(this.x0,64),x2:dump(this.x2,64),x2d:deref(this.x2,64),x3:dump(this.x3,48),x4:dump(this.x4,48)};},
    onLeave:function(r){ var out=dump(r,32)||deref(this.x0,32);
      var k='PRF|'+this.sel+'|'+(this.pre.x2||'').slice(0,32); if(seen[k])return; seen[k]=1;
      if(log.length<CAP){log.push({t:'PRF',sel:this.sel,pre:this.pre,ret:r?r.toString():null,out:out});send({k:'PRF',sel:this.sel});}}
  });
  // SM3 producer 0xa0748: message in (x0/x1) + output (x9 per memory / return)
  Interceptor.attach(base.add(0xa0748),{
    onEnter:function(a){this.x0=this.context.x0;this.x1=this.context.x1;this.x2=this.context.x2;
      this.im={x0:dump(this.x0,96),x0d:deref(this.x0,96),x1:dump(this.x1,96),x9:dump(this.context.x9,32)};},
    onLeave:function(r){var out=dump(this.x0,32);
      var k='SM3|'+(this.im.x0||this.im.x1||'').slice(0,32); if(seen[k])return; seen[k]=1;
      if(log.length<CAP){log.push({t:'SM3',in:this.im,out:out});send({k:'SM3'});}}
  });
  send({k:'INSTALLED'});
}
var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){done=true;install(b);}else{var dl=Module.findGlobalExportByName('android_dlopen_ext');
  if(dl)Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},onLeave:function(){if(done)return;if(this.p&&this.p.indexOf(MOD)>=0){var bb=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)bb=m.base;});if(bb){done=true;install(bb);}}}});}
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
