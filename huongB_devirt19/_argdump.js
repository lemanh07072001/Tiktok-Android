'use strict';
// Hook store-manager entries; dump all pointer args (x0-x7) at enter+leave to catch
// plaintext<->ciphertext. Verify prologue first. Function hooks only (tolerated).
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var ENTRIES=[0xddac4,0xdcadc,0xd9038];
var log=[]; var CAP=300; var seen={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function isPtr(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function dumpArgs(ctx,tag){
  var regs=[ctx.x0,ctx.x1,ctx.x2,ctx.x3,ctx.x4,ctx.x5,ctx.x6,ctx.x7];
  var a=[];
  for(var i=0;i<8;i++){var r=regs[i];var o={i:i,v:r?r.toString():null};
    if(isPtr(r)){ try{o.hex=b2h(r.readByteArray(96));}catch(e){}
      try{var s=r.readCString(48); if(s&&/[ -~]{3,}/.test(s))o.str=s;}catch(e){} }
    a.push(o);}
  return a;
}
function prologue(off){var a=META.add(off);var w=a.readU32();
  var mn='?'; if(w===0xd503233f)mn='paciasp'; else if((w&0xffe07fff)===0xa9807bfd)mn='stp2930';
  else if((w&0xff8003ff)===0xd10003ff||(w&0xff8003ff)===0xd100c3ff)mn='sub_sp';
  else if((w&0xffc00000)===0xa9000000)mn='stp'; 
  try{return {off:'0x'+off.toString(16), w:'0x'+w.toString(16), mn:mn, dis:Instruction.parse(a).toString()};}catch(e){return{off:'0x'+off.toString(16),w:'0x'+w.toString(16),mn:mn};}
}
ENTRIES.forEach(function(off){ send({k:'PRO',p:prologue(off)}); });
ENTRIES.forEach(function(off){ try{
  Interceptor.attach(META.add(off),{
    onEnter:function(a){ this.off=off; this.ctx=this.context; this.pre=dumpArgs(this.context,'in'); },
    onLeave:function(r){
      var post=dumpArgs(this.ctx,'out');
      // dedup by (off + x0..x2 values)
      var key=off+'|'+this.pre.slice(0,3).map(function(x){return x.v;}).join(',');
      if(seen[key])return; seen[key]=1;
      if(log.length<CAP){log.push({off:'0x'+off.toString(16), ret:r?r.toString():null, pre:this.pre, post:post}); 
        send({k:'HIT', off:'0x'+off.toString(16)});}
    }
  }); send({k:'HOOKED',off:'0x'+off.toString(16)});
}catch(e){ send({k:'HOOKERR',off:'0x'+off.toString(16),e:''+e}); } });
send({k:'READY',meta:META.toString()});
rpc.exports={dump:function(){return log;},status:function(){return{n:log.length};}};
