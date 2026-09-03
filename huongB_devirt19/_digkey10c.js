'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8;
let base=null,lo=null,hi=null,active=false,started=false,flushed=0,total=0;
let calls=[];
function off(p){try{if(p.compare(lo)>=0&&p.compare(hi)<0)return p.sub(base).toInt32();}catch(e){}return -1;}
function num(r){try{return parseInt(r.toString())&0xffffffff;}catch(e){return -1;}}
function rd(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++){const c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return null;}}
function flush(){ if(calls.length){ send({t:'CALLS',part:flushed++,calls:calls}); calls=[]; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){
      if(started)return;
      const sel=num(this.context.x1);
      if(sel!==369)return;
      started=true; active=true; this.tid=Process.getCurrentThreadId();
      Stalker.follow(this.tid,{
        transform(iter){
          let ins;
          while((ins=iter.next())!==null){
            try{
              const m=ins.mnemonic;
              if(m==='bl'||m==='blr'){
                const site=ins.address;
                const isblr=(m==='blr');
                const reg=isblr?(ins.op_str||'').trim():null;
                let st=-1;
                if(!isblr){const mm=(ins.op_str||'').match(/0x[0-9a-fA-F]+/);if(mm)st=off(ptr(mm[0]));}
                iter.putCallout(function(ctx){
                  if(total>60000)return;
                  let tgt=st;
                  if(reg){try{tgt=off(ctx[reg]);}catch(e){}}
                  calls.push({s:off(site),t:tgt,x0a:asc(ctx.x0,40),x1:num(ctx.x1),x2:num(ctx.x2),x0h:rd(ctx.x0,24)});
                  total++;
                });
              }
            }catch(e){}
            iter.keep();
          }
        }
      });
    },
    onLeave(r){
      if(!active)return;
      try{Stalker.unfollow(this.tid);}catch(e){}
      try{Stalker.flush();}catch(e){}
      active=false; flush(); send({t:'END',total:total});
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>{ send({t:'mon',active:active,total:total,buf:calls.length}); if(active) flush(); },2000);
