'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO); const base=m.base;
let vmEntry=0, exitHit=0;
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString(16).padStart(16,'0');}catch(e){return'ERR';}}
function ru32(p){try{if(p.isNull())return'NULL';return p.readU32().toString(16).padStart(8,'0');}catch(e){return'ERR';}}

// VM entry counter (light)
Interceptor.attach(base.add(0x55950),{onEnter(){vmEntry++; if(vmEntry%50===1) send({t:'vm_alive',count:vmEntry});}});

// Exit path full dump
Interceptor.attach(base.add(0xedb2c),{onEnter(){
  exitHit++;
  if(exitHit>10)return;
  const c=this.context; const x25=c.x25,x22=c.x22,x1=c.x1,x23=c.x23,x20=c.x20;
  let ctl={};
  if(!x25.isNull()&&x25.compare(0x10000)>0){
    ctl.addr=x25.toString(16);
    ctl.regcount_b8=ru32(x25.add(0xb8));
    ctl.map_ptr_60=ru64(x25.add(0x60));
    ctl.map_size_6c=ru32(x25.add(0x6c));
    ctl.field_40=ru32(x25.add(0x40));
    ctl.flags_70=rp(x25.add(0x70),64);
    ctl.raw=rp(x25,0xc0);
    try{const mp=x25.add(0x60).readU64();if(mp.compare(0)!==0)ctl.map_data=rp(ptr(mp),128);}catch(e){}
  }else ctl.addr=x25.toString(16)+'(int)';
  let cb={};
  if(!x22.isNull()&&x22.compare(0x10000)>0){cb.x22=x22.toString(16);cb.fnptr=ru64(x22);try{const f=x22.readU64();if(f.compare(0)!==0)cb.code=rp(ptr(f),32);}catch(e){}}
  send({t:'exit',n:exitHit,x25:x25.toString(16),x22:x22.toString(16),x1:x1.toString(16),x23:x23.toString(16),x20:x20.toString(16),ctl:ctl,cb:cb,regfile:rp(x1,256)});
}});
send({t:'info',msg:'Dual hook installed — SCROLL TIKTOK NOW'});
