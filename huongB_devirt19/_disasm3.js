'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
var win=[0xddbac,0xdde40];
var s=[]; var a=META.add(win[0]); var end=META.add(win[1]);
function strAt(addr){try{var v=addr.readCString(40);if(v&&/[ -~]{2,}/.test(v))return v;}catch(e){}return null;}
var lastAdrp={};
while(a.compare(end)<0){ try{var ins=Instruction.parse(a);
  var extra='';
  if(ins.mnemonic==='bl'){var m=ins.opStr.match(/0x([0-9a-f]+)/);if(m){var t=ptr('0x'+m[1]);if(t.compare(META)>=0)extra=' -> META+0x'+t.sub(META).toString(16);}}
  if(ins.mnemonic==='adrp'){var rm=ins.opStr.match(/(x\d+), #0x([0-9a-f]+)/);if(rm){lastAdrp[rm[1]]=ptr('0x'+rm[2]);}}
  if(ins.mnemonic==='add'){var am=ins.opStr.match(/(x\d+), (x\d+), #0x([0-9a-f]+)/);if(am&&lastAdrp[am[2]]){var abs=lastAdrp[am[2]].add(parseInt(am[3],16));var st=strAt(abs);if(st)extra=' ; "'+st+'"';}}
  s.push('0x'+a.sub(META).toString(16)+'  '+ins.mnemonic+' '+ins.opStr+extra); a=ins.next;}
  catch(e){s.push('0x'+a.sub(META).toString(16)+' <bad>');a=a.add(4);} }
send({k:'DIS',ins:s});
