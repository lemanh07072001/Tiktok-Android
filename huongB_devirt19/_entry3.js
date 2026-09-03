'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var RAS=[0xddb9c,0xddc90,0xdcbf4,0xdc6c4,0x12fa4c];
function isSubSp(w){ return (w&0xFF8003FF)===0xD10003FF || (w&0xFF8003FF)===0xD14003FF; }
function isBoundary(w){ return w===0xd65f03c0 /*ret*/ || (w&0xfffffc1f)===0xd61f0000 /*br*/ ||
  (w&0xfc000000)===0x14000000 /*b*/ || w===0xd503201f /*nop*/ || w===0 || (w&0xffe0001f)===0xd4200000 /*brk*/; }
function findEntry(ra){var a=META.add(ra);
  var cands=[];
  for(var off=4;off<0x3000;off+=4){var p=a.sub(off);var w,wb;
    try{w=p.readU32();wb=p.sub(4).readU32();}catch(e){break;}
    if(isSubSp(w)&&isBoundary(wb)){ cands.push({entry:'0x'+p.sub(META).toString(16),dist:off,sub:'0x'+w.toString(16)}); if(cands.length>=2)break; }
  }
  return cands.length?cands[0]:{entry:null};
}
var out={}; RAS.forEach(function(ra){out['0x'+ra.toString(16)]=findEntry(ra);});
send({k:'ENTRIES',entries:out});
