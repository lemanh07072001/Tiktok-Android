'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var RAS=[0xddb9c,0xddc90,0xdcbf4,0xdc6c4,0x12fa4c,0x12f98c];
function isPro(w){
  if(w===0xd503233f)return'paciasp';
  if((w&0xffe07fff)===0xa9807bfd)return'stp2930pre';
  if((w&0xffe07fff)===0xa9007bfd)return'stp2930off';
  return null;
}
function findEntry(ra){var a=META.add(ra);
  for(var off=0;off<0x3000;off+=4){var p=a.sub(off);var w;try{w=p.readU32();}catch(e){break;}
    var mn=isPro(w); if(mn){ // ensure preceding insn is a boundary (ret/br/nop/data) OR just take first prologue
      return {entry:'0x'+p.sub(META).toString(16),mn:mn,dist:off};}}
  return {entry:null};
}
var out={}; RAS.forEach(function(ra){out['0x'+ra.toString(16)]=findEntry(ra);});
send({k:'ENTRIES',entries:out});
