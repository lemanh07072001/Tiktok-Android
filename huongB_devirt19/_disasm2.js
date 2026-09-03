'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var win=[0x12f980,0x12fb60];
var s=[]; var a=META.add(win[0]); var end=META.add(win[1]);
while(a.compare(end)<0){ try{var ins=Instruction.parse(a);
  var tgt=''; if(ins.mnemonic==='bl'){ var m=ins.opStr.match(/0x([0-9a-f]+)/); if(m){ var t=ptr('0x'+m[1]); if(t.compare(META)>=0){tgt=' -> META+0x'+t.sub(META).toString(16);} } }
  s.push('0x'+a.sub(META).toString(16)+'  '+ins.mnemonic+' '+ins.opStr+tgt); a=ins.next;}
  catch(e){s.push('0x'+a.sub(META).toString(16)+' <bad>');a=a.add(4);} }
send({k:'DIS',ins:s});
