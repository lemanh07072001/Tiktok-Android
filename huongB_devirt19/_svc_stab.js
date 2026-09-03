'use strict';
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var n=0, hooked=0;
var MODE = (typeof GMODE!=='undefined')?GMODE:'empty';
if(META){ Process.enumerateRanges('r-x').forEach(function(rg){
  if(rg.base.compare(META)<0||rg.base.compare(META.add(MSIZE))>=0)return;
  try{ Memory.scanSync(rg.base,rg.size,'01 00 00 d4').forEach(function(m){ n++;
    try{ Interceptor.attach(m.address,{onEnter:function(){ /* empty */ }}); hooked++; }catch(e){}
  }); }catch(e){}
}); }
send({k:'READY',svc:n,hooked:hooked});
rpc.exports={ping:function(){return hooked;}};
