'use strict';
// Full chain capture: 0x879d8 (state for emu) + 0x891f4 (decoder input = slot16 HEX, for verify).
// Correlate same-thread: 0x891f4 fires right after 0x879d8 returns. Capture nonzero.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var CAP=null; var done=false; var pend={};
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function hx(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){return rok(p)?hx(p.readByteArray(n)):null;}
function closure(roots,lv,budget){var wins=[];var seen={};function visit(p,l){if(l<0||!rok(p)||budget.n<=0)return;var b=p.and(ptr("0xfffffffffffff000"));var k=b.toString();if(seen[k])return;seen[k]=1;budget.n--;var d=null;try{d=b.readByteArray(0x1000);}catch(e){return;}wins.push({a:b.toString(),b64:hx(d)});if(l>0)for(var o=0;o<0x1000;o+=8){try{var q=b.add(o).readPointer();if(rok(q))visit(q,l-1);}catch(e){}}}roots.forEach(function(r){if(rok(r))visit(r,lv);});return wins;}
// find a 32-char ASCII hex string in a struct/closure (the slot16 hex)
function findHex(p){ try{
  // p is a std::string-like; try to read data. scan p's 64 bytes + deref ptrs for 32 ascii-hex
  for(var lvl=0;lvl<3;lvl++){}
  var regions=[]; if(rok(p))regions.push(p.readByteArray(64));
  for(var off=0;off<48;off+=8){try{var q=p.add(off).readPointer();if(rok(q))regions.push(q.readByteArray(48));}catch(e){}}
  for(var r=0;r<regions.length;r++){var u=new Uint8Array(regions[r]);var s='';for(var i=0;i<u.length;i++){var c=u[i];s+=((c>=48&&c<=57)||(c>=97&&c<=102))?String.fromCharCode(c):' ';}
    var m=s.match(/[0-9a-f]{32}/); if(m)return m[0];}
  return null;
}catch(e){return null;}}
function install(base){
  Interceptor.attach(base.add(0x879d8),{
    onEnter:function(a){ if(done)return; if((this.context.x1?this.context.x1.toInt32():-1)!==0x171)return;
      var c=this.context; var regs={};
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28'].forEach(function(r){regs[r]=c[r]?c[r].toString():'0';});
      regs.fp=c.fp.toString();regs.lr=c.lr.toString();regs.sp=c.sp.toString();regs.pc=c.pc.toString();
      var url=null;try{url=c.x2.readCString(120);}catch(e){}
      var cl=closure([c.x0,c.x2,c.x3,c.sp,c.x8,c.x19,c.x20],3,{n:180});
      pend[this.threadId]={regs:regs,url:url,closure:cl,stack:{a:c.sp.sub(0x40).toString(),b64:rd(c.sp.sub(0x40),0x800)}};
    }
  });
  Interceptor.attach(base.add(0x891f4),{
    onEnter:function(a){ if(done)return; var p=pend[this.threadId]; if(!p)return;
      var hex=findHex(this.context.x0);  // decoder input = the slot16 hex
      if(!hex||/^0+$/.test(hex)){ return; }  // want nonzero
      done=true;
      CAP={base:META.toString(),msize:MSIZE,regs:p.regs,url:p.url,stack:p.stack,closure:p.closure,slot16_hex:hex};
      send({k:'CAPTURED',url:p.url,slot16_hex:hex});
    }
  });
  send({k:'INSTALLED'});
}
var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){install(b);}else{var dl=Module.findGlobalExportByName('android_dlopen_ext');Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},onLeave:function(){if(this.p&&this.p.indexOf(MOD)>=0){var bb=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)bb=m.base;});if(bb)install(bb);}}});}
send({k:'READY'});
rpc.exports={status:function(){return{has:CAP!==null};},meta:function(){return CAP?{base:CAP.base,msize:CAP.msize,regs:CAP.regs,url:CAP.url,stack:CAP.stack,slot16_hex:CAP.slot16_hex}:null;},closure:function(){return CAP?CAP.closure:null;},sochunk:function(off,len){try{return hx(META.add(off).readByteArray(len));}catch(e){return null;}}};
