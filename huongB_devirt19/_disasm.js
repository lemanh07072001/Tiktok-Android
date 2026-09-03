'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var WINS=(typeof WINDOWS!=='undefined')?WINDOWS:[[0xdda40,0xddbb0],[0xdc9c0,0xdcc00]];
var out=[];
WINS.forEach(function(win){
  var s=[];
  var a=META.add(win[0]); var end=META.add(win[1]);
  while(a.compare(end)<0){
    try{var ins=Instruction.parse(a); s.push('0x'+a.sub(META).toString(16)+'  '+ins.mnemonic+' '+ins.opStr); a=ins.next;}
    catch(e){ s.push('0x'+a.sub(META).toString(16)+'  <bad>'); a=a.add(4); }
  }
  out.push({win:'0x'+win[0].toString(16)+'-0x'+win[1].toString(16), ins:s});
});
send({k:'DIS',out:out});
