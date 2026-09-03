'use strict';var B=null;(function i(){var ms=Process.enumerateModules();for(var k=0;k<ms.length;k++)if(ms[k].name.indexOf('libmetasec')>=0)B=ms[k].base;if(!B){setTimeout(i,300);return;}
send({k:'BASE',b:B.toString()});
var a=0,b=0,c=0;
Interceptor.attach(B.add(0xa0748),{onEnter:function(){a++;}});
Interceptor.attach(B.add(0x9fdac),{onEnter:function(){b++;}});
setInterval(function(){send({prim:a,drv9fdac:b});},2000);})();
