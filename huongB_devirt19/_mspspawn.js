'use strict';
// SPAWN-gating: catch sdi_v2 device-secret crypt at STARTUP. Filter the 3 store crypts
// by RETURN-ADDRESS == store-write call-sites (isolates from request-signing firehose).
// 0x10bbd0<-0x1184a8(K0), 0x10dce0<-0x1184cc(XXTEA), 0x10c158<-0x118504(K1).
var MOD='libmetasec_ov.so'; var log=[]; var CAP=400; var done=false;
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function tt(p){try{if(!rok(p))return null;var cap=p.readU32(),size=p.add(4).readU32(),data=p.add(8).readPointer();
  if(size>0&&size<32768&&cap>=size&&rok(data))return {sz:size,hex:b2h(data.readByteArray(Math.min(size,900)))};}catch(e){}return null;}
function install(base){
  var SITES=[[0x10bbd0,0x1184a8,'K0'],[0x10dce0,0x1184cc,'XXTEA'],[0x10c158,0x118504,'K1']];
  SITES.forEach(function(s){var fn=base.add(s[0]),ret=base.add(s[1]);
    try{ Interceptor.attach(fn,{
      onEnter:function(a){ if(!this.returnAddress.equals(ret))return; // ONLY store calls
        this.hit=true; this.x20=this.context.x20; this.x0=this.context.x0; this.x1=this.context.x1;
        this.inp=tt(this.x20); this.pre0=tt(this.x0); this.pre1=tt(this.x1);},
      onLeave:function(r){ if(!this.hit)return;
        if(log.length<CAP){log.push({kind:s[2], pre0:this.pre0, pre1:this.pre1, post0:tt(this.x0), post1:tt(this.x1)}); send({k:'STORE',kind:s[2]});}}
    }); }catch(e){send({k:'ERR',fn:s[2],e:''+e});} });
  send({k:'INSTALLED',base:base.toString()});
}
// deferred module load (spawn: libmetasec loads late)
var b=null; Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){done=true;install(b);} else {
  var dl=Module.findGlobalExportByName?Module.findGlobalExportByName('android_dlopen_ext'):null;
  if(dl)Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},
    onLeave:function(){if(done)return;if(this.p&&this.p.indexOf(MOD)>=0){var bb=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)bb=m.base;});if(bb){done=true;install(bb);}}}});
  send({k:'WAIT_DLOPEN'});
}
rpc.exports={dump:function(){return log;},status:function(){return{done:done,n:log.length};}};
