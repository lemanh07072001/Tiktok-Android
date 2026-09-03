'use strict';
// dig-key: retrieved-vs-computed cho hexstr32. Hook producer 0x879d8 + Rb_tree find 0x8913c + decoder 0x891f4.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DEC=0x891f4, RBFIND=0x8913c;
let base=null; const active={}; // tid -> {sel,ctx,finds:[]}
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++){const c=u[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function cstr(p){try{return p.readUtf8String(160);}catch(e){try{return p.readCString(160);}catch(e2){return null;}}}
// đọc std::string libc++ theo cả 2 khả năng (long: dataptr@+16,size@+8; short: inline@+1)
function rdstr(p){ if(p.isNull())return null; try{
  const b0=p.readU8();
  const isLong=(b0&1)!==0;
  if(isLong){ let size=0; try{size=p.add(8).readU64().valueOf();}catch(e){size=p.add(8).readU32();}
    let dp=null; try{dp=p.add(16).readPointer();}catch(e){}
    const n=Math.min(48, Number(size)||0);
    return {L:1,size:Number(size),data:dp&&hx(dp,n),ascii:dp&&asc(dp,n)};
  } else { const size=b0>>1; const n=Math.min(22,size);
    return {L:0,size:size,ascii:asc(p.add(1),n),data:hx(p.add(1),n)}; }
}catch(e){return null;} }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(){const c=this.context,tid=this.threadId;
      let sel=null; try{sel=(parseInt(c.x1.toString())&0xffffffff);}catch(e){}
      let url=cstr(c.x2); if(url===null){try{url=cstr(c.x2.readPointer());}catch(e){}}
      active[tid]={sel:sel,url:url,ctx:c.x0,ctxhex:hx(c.x0,64),finds:[]};
    },
    onLeave(){const tid=this.threadId; const a=active[tid]; if(a){
      send({t:'PROD',tid:tid,ts:Date.now(),sel:a.sel,url:a.url,ctxhex:a.ctxhex,nfinds:a.finds.length,finds:a.finds});
      delete active[tid];
    }}
  });
  Interceptor.attach(base.add(RBFIND),{
    onEnter(){const tid=this.threadId; if(!active[tid])return; const c=this.context;
      this._tid=tid; this._x0=c.x0; this._x1=c.x1;
      // key có thể là int* hoặc std::string*; dump cả hai
      let key_int=null,key_str=null; try{key_int=c.x1.readU32();}catch(e){} 
      try{key_str=rdstr(c.x1);}catch(e){}
      this._keyi=key_int; this._keys=key_str;
    },
    onLeave(rv){const tid=this._tid; if(!tid||!active[tid])return; const a=active[tid];
      let node=null; try{node=rv;}catch(e){}
      // node giá trị: thử pair<int,string> (val@+0x28) & pair<string,string> & raw window
      let val_a=null,val_b=null,win=null;
      try{win=hx(node.add(0x20),0x40);}catch(e){}
      try{val_a=rdstr(node.add(0x28));}catch(e){}   // key=int → string@0x28
      try{val_b=rdstr(node.add(0x38));}catch(e){}   // key=string(24) → string@0x38
      if(a.finds.length<12) a.finds.push({keyi:this._keyi,keys:this._keys,node:node&&node.toString(),win:win,valA:val_a,valB:val_b});
    }
  });
  Interceptor.attach(base.add(DEC),{
    onEnter(){const c=this.context;try{this._x8=c.x8;this._x0=c.x0;this._inlen=ptr(c.x0).add(4).readU32();}catch(e){this._x8=null;}},
    onLeave(){if(!this._x8)return;try{
      const outlen=ptr(this._x8).add(4).readU32(); if(outlen!==16)return;
      const dptr=ptr(this._x8).add(8).readPointer(); const slot16=hx(dptr,16);
      let in_ascii=null; try{const ip=ptr(this._x0).add(8).readPointer();in_ascii=asc(ip,this._inlen);}catch(e){}
      const tid=this.threadId; const a=active[tid];
      send({t:'DEC',tid:tid,ts:Date.now(),slot16:slot16,hexstr:in_ascii,sel:a&&a.sel,url:a&&a.url});
    }catch(e){}}
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){try{this.p=a[0].readCString();}catch(e){}},
  onLeave(){if(this.p&&this.p.indexOf(SO)>=0) install();}
});
setInterval(()=>send({t:'mon'}),5000);
