'use strict';
// SVC store-I/O catcher v2: STATIC pre-filter — hook only svc sites whose preceding
// mov w8/x8,#imm is a FILE syscall. Avoids ANR from hooking all 188 sites.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var DIR_RE=/msdata|mssdk\/ov|\/ov\//;
var NR={56:'openat',63:'read',64:'write',67:'pread64',68:'pwrite64'};
var fdpath={}; var log=[]; var CAP=3000;
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){try{return p.readByteArray(n);}catch(e){return null;}}
function bt(ctx){try{return Thread.backtrace(ctx,Backtracer.ACCURATE).map(function(a){
  if(META&&a.compare(META)>=0&&a.compare(META.add(MSIZE))<0)return'META+0x'+a.sub(META).toString(16);
  var m=Process.findModuleByAddress(a);return m?(m.name+'+0x'+a.sub(m.base).toString(16)):a.toString();}).slice(0,16);}catch(e){return null;}}
// find svc sites in exec ranges, statically resolve nr
var found=[]; 
if(META){
  Process.enumerateRanges('r-x').forEach(function(rg){
    if(rg.base.compare(META)<0||rg.base.compare(META.add(MSIZE))>=0)return;
    try{ Memory.scanSync(rg.base,rg.size,'01 00 00 d4').forEach(function(m){
      var nr=-1;
      for(var i=1;i<=8;i++){ try{ var ins=Instruction.parse(m.address.sub(4*i));
        if((ins.mnemonic==='movz'||ins.mnemonic==='mov'||ins.mnemonic==='orr')&&/\bw8\b|\bx8\b/.test(ins.opStr)){
          var mm=ins.opStr.match(/#(0x[0-9a-f]+|\d+)/); if(mm){nr=parseInt(mm[1]); break;} }
      }catch(e){} }
      if(NR[nr]) found.push({addr:m.address,nr:nr});
    }); }catch(e){}
  });
}
// hook only file-syscall svc sites
found.forEach(function(s){
  try{ Interceptor.attach(s.addr,{
    onEnter:function(){ this.nr=s.nr; this.x0=this.context.x0; this.x1=this.context.x1; this.x2=this.context.x2; this.ctx=this.context;
      if(s.nr===56){ try{this.path=this.context.x1.readUtf8String();}catch(e){this.path=null;} } },
    onLeave:function(r){
      if(this.nr===56){ if(this.path&&DIR_RE.test(this.path)){var fd=r.toInt32();if(fd>=0)fdpath[fd]=this.path;
        if(log.length<CAP){log.push({k:'OPEN',fd:fd,path:this.path,site:'0x'+s.addr.sub(META).toString(16)});send({k:'OPEN',fd:fd,path:this.path,site:'0x'+s.addr.sub(META).toString(16)});}} return; }
      var fd=this.x0.toInt32(); var path=fdpath[fd]; if(!path)return;
      var isread=(this.nr===63||this.nr===67); var len=isread?r.toInt32():(this.x2?this.x2.toInt32():0);
      var head=b2h(rd(this.x1,Math.min(len>0?len:64,640)));
      var e={k:isread?'READ':'WRITE',fd:fd,path:path,len:len,head:head,site:'0x'+s.addr.sub(META).toString(16),bt:bt(this.ctx)};
      if(log.length<CAP){log.push(e);send({k:e.k,path:path.split('/').pop(),len:len,head:head?head.slice(0,96):null,bt:e.bt?e.bt.slice(0,10):null});}
    }
  }); }catch(e){}
});
send({k:'READY',meta:META?META.toString():null,fileSvc:found.length,sites:found.map(function(s){return{a:'0x'+s.addr.sub(META).toString(16),fn:NR[s.nr]};})});
rpc.exports={status:function(){return{n:log.length};},dump:function(){return log;},clear:function(){log=[];fdpath={};return true;}};
