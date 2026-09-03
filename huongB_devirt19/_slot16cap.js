'use strict';
// Single-shot capture at slot16 producer 0x879d8 (leaf): registers + full .so runtime
// image + ctx pointer-closure + URL + output region. For unicorn replay.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var CAP=null; var done=false;
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function b64(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function closure(roots,levels,budget){
  var wins=[]; var seen={};
  function visit(p,lv){ if(lv<0||!rok(p)||budget.n<=0)return;
    var base=p.and(ptr("0xfffffffffffff000")); var k=base.toString(); if(seen[k])return; seen[k]=1; budget.n--;
    var sz=0x1000; var data=null; try{data=base.readByteArray(sz);}catch(e){return;}
    wins.push({a:base.toString(),b64:b64(data)});
    if(lv>0){ for(var off=0;off<sz;off+=8){ try{var q=base.add(off).readPointer(); if(rok(q))visit(q,lv-1);}catch(e){} } }
  }
  roots.forEach(function(r){if(rok(r))visit(r,levels);});
  return wins;
}
function install(base){
  Interceptor.attach(base.add(0x879d8),{
    onEnter:function(a){
      if(done)return; if((this.context.x1?this.context.x1.toInt32():-1)!==0x171)return;
      var _u=null; try{_u=this.context.x2.readCString(200);}catch(e){}
      var EPS=['/aweme/v2/feed/','/api/v1/cs/setting','/aweme/v1/search/bubble/','/aweme/v1/aweme/stats/','/ms/get_seed','/consent/api/combine/list/v3'];
      var _ok=false; if(_u)for(var _i=0;_i<EPS.length;_i++)if(_u.indexOf(EPS[_i])>=0){_ok=true;break;}
      if(!_ok)return;
      done=true; try{
      var c=this.context; var regs={};
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28'].forEach(function(r){regs[r]=c[r]?c[r].toString():'0';});
      regs.fp=c.fp.toString(); regs.lr=c.lr.toString(); regs.sp=c.sp.toString(); regs.pc=c.pc.toString();
      var url=null; try{url=c.x2.readCString(120);}catch(e){}
      // stack window
      var stk=null; try{stk=b64(c.sp.sub(0x40).readByteArray(0x400));}catch(e){}
      // ctx closure from x0,x2,x3
      var cl=closure([c.x0,c.x2,c.x3],2,{n:50});
      CAP={base:base.toString(),msize:MSIZE,regs:regs,url:url,stack:{a:c.sp.sub(0x40).toString(),b64:stk},closure:cl};
      send({k:'CAPTURED',url:url});}catch(e){send({k:'CAPERR',e:''+e});}
    }
  });
  send({k:'INSTALLED'});
}
var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){install(b);}else{var dl=Module.findGlobalExportByName('android_dlopen_ext');
  Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},onLeave:function(){if(this.p&&this.p.indexOf(MOD)>=0){var bb=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)bb=m.base;});if(bb)install(bb);}}});}
send({k:'READY'});
// dump .so runtime image in chunks via rpc
rpc.exports={
  status:function(){return{done:done,has:CAP!==null};},
  meta:function(){return CAP?{base:CAP.base,msize:CAP.msize,regs:CAP.regs,url:CAP.url,stack:CAP.stack}:null;},
  closure:function(){return CAP?CAP.closure:null;},
  sochunk:function(off,len){try{return b64(META.add(off).readByteArray(len));}catch(e){return null;}}
};
