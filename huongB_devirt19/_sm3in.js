'use strict';
// Hook SM3 streaming update 0x9fdac (x0=data,x1=len,x2=ctx) — thấy full message.
// #19 = query‖slot16‖0x30 ⇒ byte cuối=0x30, slot16=16B trước. Lọc theo shape.
var BASE=null;
function findBase(){var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)return ms[i].base;return null;}
function hexb(u8){var s='';for(var i=0;i<u8.length;i++){var h=u8[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function asc(u8){var s='';for(var i=0;i<u8.length;i++){var c=u8[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
(function inst(){
  BASE=findBase(); if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE',base:BASE.toString()});
  Interceptor.attach(BASE.add(0x9fdac),{
    onEnter:function(a){
      try{
        var p=a[0], n=a[1].toInt32();
        if (n<40 || n>4096) return;
        var buf=Memory.readByteArray(p,n); if(!buf) return;
        var u8=new Uint8Array(buf);
        if (u8[n-1]!==0x30) return;             // #19 kết bằng '0'
        // slot16 = 16B trước byte cuối; query = phần trước đó
        var slot=hexb(u8.slice(n-17,n-1));
        var q=asc(u8.slice(0,n-17));
        // chỉ lấy khi phần đầu là query thật (có 'os=' hoặc 'device_')
        if (q.indexOf('os=')<0 && q.indexOf('device_')<0 && q.indexOf('aid=')<0) return;
        send({k:'M19', len:n, slot16:slot, q:q.slice(0,90), datptr:p.toString(),
              ctx:a[2].toString(), lr:'0x'+this.context.lr.sub(BASE).toString(16)});
      }catch(e){}
    }
  });
  send({k:'READY'});
})();
