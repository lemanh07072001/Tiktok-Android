'use strict';
var BASE=null;
(function inst(){
  var ms=Process.enumerateModules(); for(var i=0;i<ms.length;i++) if(ms[i].name.indexOf('libmetasec')>=0) BASE=ms[i].base;
  if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE',base:BASE.toString()});
  var n=0;
  Interceptor.attach(BASE.add(0x891f4),{onEnter:function(a){
    n++;
    if(n<=12){
      try{
        send({k:'HIT',i:n,lr:'0x'+a[8]?'':'', // placeholder
              x0:a[0].toString(),x1:a[1].toString(),
              lr2:'0x'+this.context.lr.sub(BASE).toString(16),
              dumpX1:hexdump(a[1],{length:32,ansi:false})});
      }catch(e){send({k:'ERR',e:''+e});}
    }
  }});
  send({k:'READY'});
})();
