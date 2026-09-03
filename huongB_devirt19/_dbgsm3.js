'use strict';
var BASE=null;
(function inst(){
  var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)BASE=ms[i].base;
  if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE'});
  var prim=0,drv=0;
  Interceptor.attach(BASE.add(0xa0748),{onEnter:function(){prim++;}});
  Interceptor.attach(BASE.add(0xa03ac),{onEnter:function(a){
    drv++;
    if(drv<=6){
      var o={k:'DRV',n:drv,x0:a[0].toString(),x1:a[1].toString(),x2:a[2].toString()};
      try{o.d0=hexdump(a[0],{length:48,ansi:false});}catch(e){}
      try{o.d1=hexdump(a[1],{length:48,ansi:false});}catch(e){}
      send(o);
    }
  }});
  setInterval(function(){send({k:'CNT',prim:prim,drv:drv});},3000);
  send({k:'READY'});
})();
