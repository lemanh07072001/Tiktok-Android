'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8;
let base=null,lo=null,hi=null,active=false,done=false,flushed=0;
let calls=[];
function off(p){try{if(p.compare(lo)>=0&&p.compare(hi)<0)return p.sub(base).toInt32();}catch(e){}return -1;}
function rd(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++){const c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function flush(){ if(calls.length){ send({t:'CALLS',part:flushed++,calls:calls}); calls=[]; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){
      if(done||active)return;
      const sel=parseInt(this.context.x1.toString())&0xffffffff;
      if(sel!==369)return;
      active=true; this.tid=Process.getCurrentThreadId();
      Stalker.follow(this.tid,{
        transform(iter){
          let ins=iter.next();
          do{
            const m=ins.mnemonic;
            if(m==='bl'||m==='blr'){
              const site=ins.address;
              let staticT=-1, reg=null;
              if(m==='bl'){ const o=ins.op_str; if(o[0]==='#'){ try{staticT=off(ptr(o.slice(1)));}catch(e){} } }
              else { reg=ins.op_str.trim(); }
              iter.putCallout(function(ctx){
                if(calls.length+flushed*1>100000)return;
                let tgt=staticT;
                if(reg){ try{tgt=off(ctx[reg]);}catch(e){} }
                calls.push({s:off(site),t:tgt,
                  x0a:asc(ctx.x0,40),x1:(parseInt(ctx.x1.toString())&0xffffffff),
                  x2:(parseInt(ctx.x2.toString())&0xffffffff),x0h:rd(ctx.x0,24)});
              });
            }
            iter.keep();
          }while((ins=iter.next())!==null);
        }
      });
    },
    onLeave(r){
      if(!active||done)return;
      try{Stalker.unfollow(this.tid);}catch(e){}
      try{Stalker.flush();}catch(e){}
      done=true; active=false;
      flush(); send({t:'END'});
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>{ send({t:'mon',active:active,done:done,buf:calls.length,flushed:flushed}); if(active&&calls.length>0) flush(); },2500);
