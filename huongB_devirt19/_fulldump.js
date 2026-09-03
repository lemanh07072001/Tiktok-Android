'use strict';
// FULL store extraction: XXTEA core (key,plaintext,ct) + registry keynames (for labeling).
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var log=[]; var CAP=4000; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
// XXTEA core 0x152310(x0=in,x1=len,x2=key16,x3=&outlen)->ret
try{ Interceptor.attach(META.add(0x152310),{
  onEnter:function(a){this.inp=this.context.x0;this.len=this.context.x1.toInt32();this.keyp=this.context.x2;this.olp=this.context.x3;
    this.key=rok(this.keyp)?b2h(this.keyp.readByteArray(16)):null;
    this.input=(rok(this.inp)&&this.len>0&&this.len<8192)?b2h(this.inp.readByteArray(this.len)):null;},
  onLeave:function(r){var ol=-1;try{ol=this.olp.readU32();}catch(e){}var out=null;try{if(rok(r)&&ol>0&&ol<16384)out=b2h(r.readByteArray(ol));}catch(e){}
    var k='X|'+this.key+'|'+this.input;if(seen[k])return;seen[k]=1;
    if(log.length<CAP)log.push({t:'X',key:this.key,input:this.input,output:out});}
}); send({k:'HX'});}catch(e){}
// registry keyname strings via TT-string {cap,size,ptr} from persist handlers
function ttstr(A){try{if(!rok(A))return null;var cap=A.readU32(),size=A.add(4).readU32(),data=A.add(8).readPointer();
  if(size===0||size>4096||cap<size||!rok(data))return null;return b2h(data.readByteArray(Math.min(size,300)));}catch(e){return null;}}
function scan(root,depth,b){if(depth<0||!rok(root)||b.n>400)return;
  for(var off=0;off<128;off+=8){b.n++;var A=root.add(off);var s=ttstr(A);
    if(s){var kk='S|'+s;if(!seen[kk]){seen[kk]=1;if(log.length<CAP)log.push({t:'S',hex:s});}}
    if(depth>0){try{var q=A.readPointer();if(rok(q)&&q.compare(root)!==0)scan(q,depth-1,b);}catch(e){}}}}
[0x12fd3c,0x13accc].forEach(function(off){try{Interceptor.attach(META.add(off),{onEnter:function(){var b={n:0};for(var i=0;i<5;i++){var r=this.context['x'+i];if(rok(r))scan(r,3,b);}}});}catch(e){}});
send({k:'READY'});
rpc.exports={dump:function(){return log;}};
