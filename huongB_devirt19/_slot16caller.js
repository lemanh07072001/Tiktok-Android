'use strict';
// Hook unhex 0x891f4: đọc input hex (std::string @ x1) + return-address (lr)
// = call-site THẬT sinh slot16. Lọc input 32-char (slot16) vs 52-char (rtk2_ms)...
var BASE=null;
function findBase(){
  var ms=Process.enumerateModules();
  for (var i=0;i<ms.length;i++) if (ms[i].name.indexOf('libmetasec')>=0) return ms[i].base;
  return null;
}
function readStd(p){
  // libc++ std::string: LSB của byte0 = is_long. long:[cap][size][ptr]; short:[sizebyte][buf23]
  try{
    var b0=p.readU8();
    if (b0 & 1){ // long
      var size=p.add(8).readU64().toNumber();
      var ptr=p.add(16).readPointer();
      if (size>0 && size<4096) return {s:ptr.readUtf8String(size), n:size};
    } else { // short (SSO)
      var size=b0>>1;
      if (size>0 && size<24) return {s:p.add(1).readUtf8String(size), n:size};
    }
  }catch(e){}
  return null;
}
function isHex(s){ return /^[0-9a-fA-F]+$/.test(s); }

function install(){
  BASE=findBase();
  if (!BASE){ setTimeout(install,300); return; }
  send({k:'BASE',base:BASE.toString()});
  var UNHEX=BASE.add(0x891f4);
  Interceptor.attach(UNHEX,{
    onEnter:function(a){
      var inp=readStd(a[1]);   // x1 = input std::string
      if (!inp || !inp.s || !isHex(inp.s)) return;
      var lr=this.context.lr;
      var off=lr.sub(BASE);
      var rec={k:'UNHEX', hex:inp.s, len:inp.n, lr:'0x'+off.toString(16),
               tid:this.threadId};
      // đánh dấu slot16 (32-char) đặc biệt
      if (inp.n===32) rec.SLOT16=true;
      send(rec);
    }
  });
  // cũng hook map-lookup 0x8913c: key→value (xem map trả gì)
  var MAP=BASE.add(0x8913c);
  Interceptor.attach(MAP,{
    onEnter:function(a){ this.key=readStd(a[2]); this.out=a[0]; },
    onLeave:function(r){
      if (!this.key||!this.key.s) return;
      var v=readStd(this.out);
      send({k:'MAP', key:this.key.s, val:v?v.s:null, vn:v?v.n:0});
    }
  });
  send({k:'READY'});
}
install();
