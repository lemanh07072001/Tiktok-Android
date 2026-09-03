'use strict';
function region(a){ try{const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){} return '?'; }
rpc.exports={ scan:function(hexvals){
  const out=[];
  const ranges=Process.enumerateRanges('rw-');
  hexvals.forEach(hv=>{
    const pat=hv.match(/../g).join(' ');
    ranges.forEach(r=>{ try{ Memory.scanSync(r.base,r.size,pat).forEach(m=>{ out.push({slot:hv, addr:m.address.toString(), region:region(m.address)}); }); }catch(e){} });
  });
  return out;
}};
