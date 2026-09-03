'use strict';var B=null;(function i(){var ms=Process.enumerateModules();for(var k=0;k<ms.length;k++)if(ms[k].name.indexOf('libmetasec')>=0)B=ms[k].base;if(!B){setTimeout(i,300);return;}
var n=0;Interceptor.attach(B.add(0x9fdac),{onEnter:function(){n++;}});setInterval(function(){send({n:n});},2000);send({k:'R'});})();
