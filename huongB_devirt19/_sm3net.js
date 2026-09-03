'use strict';
// 0x9fdac(x0=data,x1=len). Đọc bằng readU8() thuần — KHÔNG Uint8Array, KHÔNG toInt32, KHÔNG lr.
var BASE=null;
function findBase(){var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)return ms[i].base;return null;}
function H(b){var h=b.toString(16);return (h.length<2?'0':'')+h;}
(function inst(){
  BASE=findBase(); if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE',base:BASE.toString()});
  Interceptor.attach(BASE.add(0x9fdac),{
    onEnter:function(a){
      try{
        var p=a[0];
        var n=parseInt(a[1].toString().substr(2),16); if(!(n>=16&&n<=8192)) return;
        // head ascii (20B)
        var head='';
        for(var i=0;i<20&&i<n;i++){var c=p.add(i).readU8();head+=(c>=32&&c<127)?String.fromCharCode(c):'.';}
        if(n<=128){
          var hx='';
          for(var j=0;j<n;j++) hx+=H(p.add(j).readU8());
          send({k:'S',len:n,hex:hx});
        } else {
          if(head.indexOf('os=')>=0||head.indexOf('device_')>=0||head.indexOf('scene=')>=0||head.indexOf('aid=')>=0||head.indexOf('room_id')>=0){
            var tail='';
            for(var t=n-34;t<n;t++) tail+=H(p.add(t).readU8());
            send({k:'L',len:n,tail:tail,last:p.add(n-1).readU8(),head:head});
          }
        }
      }catch(e){send({k:'ERR',e:''+e});}
    }
  });
  send({k:'READY'});
})();
