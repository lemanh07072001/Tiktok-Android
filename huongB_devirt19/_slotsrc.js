const m=Process.findModuleByName('libmetasec_ov.so'), base=m.base, end=base.add(m.size);
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function rel(p){if(p.compare(base)>=0&&p.compare(end)<0)return 'so+0x'+p.sub(base).toString(16);const mm=Process.findModuleByAddress(p);return mm?mm.name+'+0x'+p.sub(mm.base).toString(16):p.toString();}
let n=0;
Interceptor.attach(Module.findGlobalExportByName('memcpy'),{onEnter(a){
  if(n>=5)return; if(a[2].toInt32()!==16)return;
  const dst=a[0], src=a[1];
  // is dst appending after a query? check 20 bytes before dst for ascii digits/'=' (device_id tail)
  let pre; try{pre=new Uint8Array(dst.sub(20).readByteArray(20));}catch(e){return;}
  let ascii=0; for(let i=0;i<20;i++){const c=pre[i]; if((c>=48&&c<=57)||c===61||c===38||c===95)ascii++;}
  if(ascii<12) return;                          // dst not preceded by query text
  // where does src point? dump src region + who owns it
  const rng=Process.findRangeByAddress(src);
  n++;
  send({t:'SRC', slot16:hx(src,16), srcPtr:src.toString(), srcRel:rel(src),
        srcRange: rng?(rng.protection+' '+(rng.file?rng.file.path:'anon')+' base='+rng.base):'?',
        srcRegion:hx(src.sub(32),96),
        dstPre:String.fromCharCode.apply(null,pre),
        bt:Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,6).map(rel)});
}});
send({t:'info',msg:'slotsrc ready'});
