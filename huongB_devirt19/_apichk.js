'use strict';
try{ send({t:'v', hasFindExport: (typeof Module.findExportByName), hasGetGlobal:(typeof Module.getGlobalExportByName), hasFindGlobal:(typeof Module.findGlobalExportByName)}); }catch(e){ send({t:'err',e:String(e)}); }
try{
  let cands=['libc++_shared.so','libc++.so','libc.so'];
  let out={};
  for(const mn of cands){
    let m=Process.findModuleByName(mn);
    if(!m){ out[mn]='(not loaded)'; continue; }
    let a=null;
    try{ a=m.getExportByName? m.getExportByName('_Znwm'): null; }catch(e){ a='(no _Znwm)'; }
    out[mn]= a? a.toString():'(null)';
  }
  send({t:'znwm', out:out});
}catch(e){ send({t:'err2',e:String(e)}); }
