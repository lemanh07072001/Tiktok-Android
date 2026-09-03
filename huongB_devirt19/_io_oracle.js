'use strict';
function res(mod,sym){ var m=Process.findModuleByName(mod); return m?m.findExportByName(sym):null; }
function cstr(p){ try{return p.readCString();}catch(e){return null;} }
var fdpath={};      // fd -> path (for .ms/.dy files)
var RE=/\.(ms[a-z0-9]*|dy)\b|\/tasks\/|mssdk/;
function hook(sym, pathArgIdx){
  var f=res('libc.so',sym); if(!f) return;
  Interceptor.attach(f,{ onEnter:function(a){ this.p=cstr(this.context['x'+pathArgIdx]); },
    onLeave:function(r){ if(this.p&&RE.test(this.p)){ var fd=r.toInt32(); if(fd>=0){ fdpath[fd]=this.p; console.log('[OPEN fd='+fd+'] '+this.p);} } } });
}
hook('open',0); hook('openat',1);
// read(fd,buf,cnt): x0=fd x1=buf. dump on return if fd is a tracked store file
['read','pread64'].forEach(function(sym){
  var f=res('libc.so',sym); if(!f) return;
  Interceptor.attach(f,{ onEnter:function(a){ this.fd=this.context.x0.toInt32(); this.buf=this.context.x1; },
    onLeave:function(r){ var n=r.toInt32(); if(n>0 && fdpath[this.fd]){ var m=Math.min(n,256); var ab; try{ab=this.buf.readByteArray(m);}catch(e){ab=null;} var u=ab?new Uint8Array(ab):[]; var s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=h.length<2?'0'+h:h;} console.log('[READ fd='+this.fd+' n='+n+'] '+fdpath[this.fd]+' :: '+s);} } });
});
console.log('[IO ORACLE loaded]');
