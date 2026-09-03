'use strict';
function region(a){ try{const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){} return '?'; }
rpc.exports={ scan:function(hexvals){
  const out=[]; const ranges=Process.enumerateRanges('rw-');
  for(let ri=0;ri<ranges.length;ri++){ const r=ranges[ri];
    if(r.size>0x2000000) continue;   // skip >32MB
    for(let hi=0;hi<hexvals.length;hi++){ const pat=hexvals[hi].match(/../g).join(' ');
      try{ const ms=Memory.scanSync(r.base,r.size,pat); for(let k=0;k<ms.length;k++){ out.push({slot:hexvals[hi],addr:ms[k].address.toString(),region:region(ms[k].address)}); } }catch(e){}
    }
    if(out.length>=30) break;
  }
  return out;
}};
send({t:'i',msg:'scan2 ready'});
