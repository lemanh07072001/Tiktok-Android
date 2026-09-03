'use strict';
// Capture a NONZERO-slot16 0x879d8 call at startup: onEnter full state (for emu) +
// onLeave ctx scan for the produced nonzero slot16. Cross-check via 0x9fdac (DRV reads slot16).
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var CAP=null; var done=false; var lastDrvSlot=null;
function rok(p){try{if(!p||p.isNull())return false;var r=Process.findRangeByAddress(p);return !!r&&r.protection[0]==='r';}catch(e){return false;}}
function hx(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rd(p,n){return rok(p)?hx(p.readByteArray(n)):null;}
function closure(roots,levels,budget){var wins=[];var seen={};
  function visit(p,lv){if(lv<0||!rok(p)||budget.n<=0)return;var base=p.and(ptr("0xfffffffffffff000"));var k=base.toString();if(seen[k])return;seen[k]=1;budget.n--;
    var data=null;try{data=base.readByteArray(0x1000);}catch(e){return;}wins.push({a:base.toString(),b64:hx(data)});
    if(lv>0)for(var off=0;off<0x1000;off+=8){try{var q=base.add(off).readPointer();if(rok(q))visit(q,lv-1);}catch(e){}}}
  roots.forEach(function(r){if(rok(r))visit(r,levels);});return wins;}
function isHash(h){ if(!h||h.length<32)return false; // 16B, not all-zero, not pointer-looking (76.../78... repeated)
  if(/^0+$/.test(h))return false; var b=h.slice(0,32);
  // pointer heuristic: bytes 5-7 = 0x76/0x77/0x78 + trailing 00 → skip
  return true; }
function install(base){
  // DRV 0x9fdac: read slot16 (x0[0:16], x1==16, nonzero) for cross-check
  Interceptor.attach(base.add(0x9fdac),{onEnter:function(a){try{
    if((this.context.x1.toInt32()&0xffffffff)!==16)return; var v=rd(this.context.x0,16);
    if(v&&!/^0+$/.test(v))lastDrvSlot={tid:this.threadId,val:v};
  }catch(e){}}});
  // PROD 0x879d8: capture full state, find nonzero slot16 in ctx at onLeave
  Interceptor.attach(base.add(0x879d8),{
    onEnter:function(a){ if(done)return; if((this.context.x1?this.context.x1.toInt32():-1)!==0x171)return;
      this.c=this.context; var c=this.context;
      this.pre_ctx=rd(c.x0,256);
      this.snap={regs:{},url:null};
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28'].forEach(function(r){c[r]&&(0);});
      var regs={};['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28'].forEach(function(r){regs[r]=c[r]?c[r].toString():'0';});
      regs.fp=c.fp.toString();regs.lr=c.lr.toString();regs.sp=c.sp.toString();regs.pc=c.pc.toString();
      this.regs=regs; try{this.url=c.x2.readCString(120);}catch(e){this.url=null;}
      this.stack={a:c.sp.sub(0x40).toString(),b64:rd(c.sp.sub(0x40),0x400)};
      this.x0=c.x0; this.x2=c.x2; this.x3=c.x3;
    },
    onLeave:function(r){ if(done||!this.c)return;
      // scan a WIDE stack region for a 32-char ASCII hex string (= slot16 hex @sp+0x190)
      var sp=this.c.sp; var found=null;
      try{ var reg=sp.sub(0x100).readByteArray(0x400); var u=new Uint8Array(reg); var s='';
        for(var i=0;i<u.length;i++){var c=u[i]; s+=((c>=48&&c<=57)||(c>=97&&c<=102))?String.fromCharCode(c):' ';}
        var m=s.match(/[0-9a-f]{32}/); if(m && !/^0+$/.test(m[0])) found=m[0];
      }catch(e){}
      // also scan closure heap windows for the hex string (std::string data on heap)
      if(!found){ var cl2=closure([this.x0,this.x2,this.x3,this.c.sp],2,{n:60});
        for(var w=0;w<cl2.length;w++){ var hxs=cl2[w].b64; var bb=[]; for(var j=0;j<hxs.length;j+=2)bb.push(parseInt(hxs.substr(j,2),16));
          var ss=''; for(var k=0;k<bb.length;k++){var cc=bb[k]; ss+=((cc>=48&&cc<=57)||(cc>=97&&cc<=102))?String.fromCharCode(cc):' ';}
          var mm=ss.match(/[0-9a-f]{32}/); if(mm && !/^0+$/.test(mm[0]) && mm[0].indexOf('00000000')<0){found=mm[0]; break;} } }
      if(found){ done=true; var foundOff=-1;
        var cl=closure([this.x0,this.x2,this.x3],2,{n:50});
        CAP={base:META.toString(),msize:MSIZE,regs:this.regs,url:this.url,stack:this.stack,closure:cl,
             slot16:found,slot16_off:foundOff,drvSlot:lastDrvSlot?lastDrvSlot.val:null};
        send({k:'CAPTURED',url:this.url,slot16:found,off:foundOff}); }
    }
  });
  send({k:'INSTALLED'});
}
var b=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){install(b);}else{var dl=Module.findGlobalExportByName('android_dlopen_ext');
  Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},onLeave:function(){if(this.p&&this.p.indexOf(MOD)>=0){var bb=null;Process.enumerateModules().forEach(function(m){if(m.name===MOD)bb=m.base;});if(bb)install(bb);}}});}
send({k:'READY'});
rpc.exports={status:function(){return{has:CAP!==null};},meta:function(){return CAP?{base:CAP.base,msize:CAP.msize,regs:CAP.regs,url:CAP.url,stack:CAP.stack,slot16:CAP.slot16,slot16_off:CAP.slot16_off,drvSlot:CAP.drvSlot}:null;},closure:function(){return CAP?CAP.closure:null;},sochunk:function(off,len){try{return hx(META.add(off).readByteArray(len));}catch(e){return null;}}};
