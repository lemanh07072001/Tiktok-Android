'use strict';
var BASE=null;
(function inst(){
  var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)BASE=ms[i].base;
  if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE'});
  var n=0;
  Interceptor.attach(BASE.add(0x9fdac),{onEnter:function(a){
    n++;
    if(n<=14){
      var o={k:'C',n:n,x0:a[0].toString(),x1:a[1].toString(),x2:a[2].toString()};
      try{o.d=hexdump(a[0],{length:64,ansi:false});}catch(e){o.d='(x0 unreadable)';}
      send(o);
    }
  }});
  send({k:'READY'});
})();
