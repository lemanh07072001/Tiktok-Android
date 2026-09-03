'use strict';
// Given store-manager return addresses, find each containing function's entry
// (scan backward for paciasp / prologue / preceding ret), report offsets.
var MOD='libmetasec_ov.so'; var META=null,MSIZE=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){META=m.base;MSIZE=m.size;}});
var RAS=[0xddb9c,0xddc90,0xdcbf4,0xdc6c4,0xd922c,0x69094,0x697a8,0x12fa4c];
function findEntry(ra){
  var a=META.add(ra);
  // scan backward up to 0x1000 bytes
  for(var off=0; off<0x1000; off+=4){
    var p=a.sub(off);
    var w; try{w=p.readU32();}catch(e){break;}
    if(w===0xd503233f){ return {entry:'0x'+p.sub(META).toString(16), by:'paciasp', dist:off}; } // paciasp
    // stp x29,x30,[sp,#-imm]! : top bits 0xA9 .. matches 0xa9b?7bfd
    if((w&0xffe07fff)===0xa9807bfd){ return {entry:'0x'+p.sub(META).toString(16), by:'stp2930', dist:off}; }
    // preceding ret (0xd65f03c0): entry likely just after
    if(w===0xd65f03c0 && off>0){ return {entry:'0x'+p.add(4).sub(META).toString(16), by:'after-ret', dist:off}; }
  }
  return {entry:null};
}
var out={};
RAS.forEach(function(ra){ out['0x'+ra.toString(16)]=findEntry(ra); });
send({k:'ENTRIES', meta:META.toString(), entries:out});
