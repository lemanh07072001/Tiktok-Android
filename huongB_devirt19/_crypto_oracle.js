'use strict';
// LEAN CRYPTO ORACLE: arm via libc openat (no libmetasec .text touch),
// hook all 4 AES key/cipher-init variants inside libmetasec, send each immediately.
var MOD='libmetasec_ov.so';
var base=null;
var INITS=[['E0',0x159d60],['KS',0x1591bc],['E192',0x15a1dc],['E256',0x15a598]];
var STORE_RE=/mssdk\/ov|\.ms[spf3]/;
var armUntil=0, curPath=null, seen={};
function b2h(ab){ if(!ab)return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;} return s; }
function rN(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }
// libc openat arm (safe, outside libmetasec)
try{
  var oa=Module.getExportByName('libc.so','openat');
  Interceptor.attach(oa,{ onEnter:function(a){ var p=null; try{p=a[1].readUtf8String();}catch(e){}
    if(p&&STORE_RE.test(p)){ curPath=p; armUntil=Date.now()+800; send({tag:'OPEN',path:p}); } }});
}catch(e){ send({tag:'ERR',e:'openat '+e}); }
function armLibmeta(){
  base=Process.getModuleByName(MOD).base;
  send({tag:'BASE',base:base.toString()});
  INITS.forEach(function(it){
    var nm=it[0], off=it[1];
    try{
      Interceptor.attach(base.add(off),{
        onEnter:function(a){
          var kb=-1; try{kb=a[2].toInt32();}catch(e){}
          var n=(kb>0&&kb<=64)?kb:32;
          var key=null,iv=null,k2=null;
          try{key=b2h(rN(a[1],n));}catch(e){}
          try{k2=b2h(rN(a[1],32));}catch(e){}
          try{iv=b2h(rN(a[3],16));}catch(e){}
          var armed=(Date.now()<=armUntil);
          var dk=nm+'|'+k2+'|'+iv+'|'+kb;
          if(seen[dk]&&!armed) return; seen[dk]=1;
          send({tag:'INIT',which:nm,armed:armed,path:armed?curPath:null,keyBytes:kb,key:key,key32:k2,iv:iv});
        }
      });
    }catch(e){ send({tag:'ERR',e:nm+' '+e}); }
  });
  send({tag:'HOOKS_ARMED',n:INITS.length});
}
var t=setInterval(function(){ if(Process.findModuleByName(MOD)){ clearInterval(t); try{armLibmeta();}catch(e){send({tag:'ERR',e:''+e});} } },15);
send({tag:'READY'});
