'use strict';
// 0x9fdac(x0=data,x1=len,x2=ctx) single-shot SM3. Bắt:
//  (A) message ngắn (len<=96) TRỌN VẸN — gồm cái SIGN_KEY‖nonce‖SIGN_KEY (len=68) nghi là producer slot16
//  (B) message có query — dump TAIL 48B để tìm cái kết 0x30 (=#19, slot16=16B trước)
var BASE=null;
function findBase(){var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)return ms[i].base;return null;}
function hexb(u8){var s='';for(var i=0;i<u8.length;i++){var h=u8[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function asc(u8){var s='';for(var i=0;i<u8.length;i++){var c=u8[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
(function inst(){
  BASE=findBase(); if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE'});
  Interceptor.attach(BASE.add(0x9fdac),{
    onEnter:function(a){
      try{
        var n=a[1].toInt32(); if(n<16||n>8192) return;
        var buf=Memory.readByteArray(a[0],n); if(!buf) return;
        var u8=new Uint8Array(buf);
        if (n<=96){                     // (A) message ngắn — trọn vẹn
          send({k:'SHORT',len:n,hex:hexb(u8),lr:'0x'+this.context.lr.sub(BASE).toString(16)});
        } else {                        // (B) message dài — head+tail
          var head=asc(u8.slice(0,24));
          if (head.indexOf('os=')<0 && head.indexOf('device_')<0 && head.indexOf('scene=')<0 && head.indexOf('aid=')<0) return;
          var tail=u8.slice(n-33);      // 33B cuối
          send({k:'LONG',len:n,tailhex:hexb(tail),lastbyte:u8[n-1],head:head});
        }
      }catch(e){}
    }
  });
  send({k:'READY'});
})();
