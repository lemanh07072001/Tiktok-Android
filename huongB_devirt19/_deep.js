'use strict';
// Hook the 3 concrete store handlers; deep-follow every pointer field (3 levels)
// to extract the key/value plaintext. Report buffers that are printable or match on-disk ct.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var HANDLERS=[0x12fb50,0x12fd3c,0x13accc];
var log=[]; var CAP=200; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function ascii(ab){var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var c=u[i];s+=(c>=32&&c<=126)?String.fromCharCode(c):'.';}return s;}
function readable(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function follow(p,depth,acc,path){
  if(depth<0||!readable(p))return;
  var hx=null; try{hx=b2h(p.readByteArray(96));}catch(e){return;}
  if(!hx)return;
  var asc=ascii(p.readByteArray(96));
  var pr=0; var b=p.readByteArray(96); var u=new Uint8Array(b); for(var i=0;i<u.length;i++)if(u[i]>=32&&u[i]<=126)pr++;
  pr/=u.length;
  if(pr>0.55 || /sdi_v2|mssdk|msf|device|\{"/.test(asc)) acc.push({path:path, addr:p.toString(), pr:+pr.toFixed(2), ascii:asc, hex:hx.slice(0,64)});
  // deref each 8-byte word that looks like a heap pointer
  for(var off=0;off<48;off+=8){ try{var q=p.add(off).readPointer(); if(readable(q)) follow(q,depth-1,acc,path+'+'+off+'>'); }catch(e){} }
}
HANDLERS.forEach(function(off){ try{
  Interceptor.attach(META.add(off),{
    onEnter:function(a){ this.off=off; this.ctx=this.context;
      this.acc=[]; for(var i=0;i<5;i++){ var r=this.context['x'+i]; if(readable(r)) follow(r,2,this.acc,'x'+i); } this.pre=this.acc; },
    onLeave:function(r){ var acc=[]; for(var i=0;i<5;i++){ var rr=this.ctx['x'+i]; if(readable(rr)) follow(rr,2,acc,'x'+i); }
      if(readable(r)) follow(r,2,acc,'ret');
      var key=off+'|'+(this.pre.length?this.pre[0].ascii.slice(0,12):'');
      if(seen[key])return; seen[key]=1;
      if(log.length<CAP) log.push({handler:'0x'+off.toString(16), pre:this.pre, post:acc});
    }
  }); }catch(e){} });
send({k:'READY'});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
