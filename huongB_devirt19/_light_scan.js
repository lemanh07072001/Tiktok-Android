'use strict';
const seen={};
['openat','__openat','open'].forEach(function(fn){
  const p=Module.findGlobalExportByName(fn); if(!p)return;
  Interceptor.attach(p,{onEnter(a){
    try{const path=(fn.indexOf('openat')>=0)?a[1].readCString():a[0].readCString();
      if(path&&/^\/(proc|sys)/.test(path)&&!seen[path]){seen[path]=1;send({t:'F',path:path});}
    }catch(e){}
  }});
});
send({t:'info',msg:'light installed'});
