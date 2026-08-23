const m=Process.findModuleByName('libmetasec_ov.so'), base=m.base, end=base.add(m.size);
function rel(p){if(p.compare(base)>=0&&p.compare(end)<0)return 'so+0x'+p.sub(base).toString(16);const mm=Process.findModuleByAddress(p);return mm?mm.name+'+0x'+p.sub(mm.base).toString(16):p.toString();}
const seen={}; let n=0;
Interceptor.attach(base.add(0xa0748),{onEnter(){
  if(n>=200)return; n++;
  let bt; try{bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,7).map(rel);}catch(e){return;}
  const key=bt.slice(1,5).join(' <- ');   // caller chain (skip SM3 itself)
  seen[key]=(seen[key]||0)+1;
}});
setInterval(()=>{const t=Object.entries(seen).sort((a,b)=>b[1]-a[1]).slice(0,6);send({t:'info',msg:'SM3 callers:\n'+t.map(e=>'  ['+e[1]+'] '+e[0]).join('\n')});},4000);
send({t:'info',msg:'bt ready'});
