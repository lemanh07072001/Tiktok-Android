'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748, MD5=0x15b594;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function asc(u,a,b){let s='';for(let i=a;i<b;i++)s+=String.fromCharCode(u[i]);return s;}

// Track recent MD5 outputs (with their full input)
const recentMD5=[];  // {input, output}
Interceptor.attach(base.add(MD5),{
  onEnter(){ const c=this.context; const len=c.x1.toInt32();
    this.len=len; this.out=c.x2;
    this.inp=(len>0&&len<8192)?hx(c.x0,Math.min(len,2048)):null; },
  onLeave(){ if(this.inp){ const o=hx(this.out,16);
    recentMD5.push({inhex:this.inp,len:this.len,out:o});
    if(recentMD5.length>50)recentMD5.shift(); } }
});

// SM3 slot16 capture (note 33 method)
const chain={};
Interceptor.attach(base.add(SM3),{onEnter(){
  const tid=this.threadId; let st,inp;
  try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){return;}
  if(st===IV_LE)chain[tid]=Array.from(inp);
  else if(chain[tid]){for(let i=0;i<64;i++)chain[tid].push(inp[i]);}
  else return;
  const a=chain[tid],L=a.length;
  if(L<9)return;
  let bl=0;for(let i=L-8;i<L;i++)bl=bl*256+a[i];
  const ml=bl/8;
  if(!(ml>16&&ml<L)||a[ml]!==0x80)return;
  if(a[ml-1]!==0x30||ml<200){delete chain[tid];return;}
  let slot='';for(let i=ml-17;i<ml-1;i++)slot+=('0'+a[i].toString(16)).slice(-2);
  // find matching md5 output
  let matchIdx=-1;
  for(let k=recentMD5.length-1;k>=0;k--){ if(recentMD5[k].out===slot){matchIdx=k;break;} }
  const match=matchIdx>=0?recentMD5[matchIdx]:null;
  send({t:'LINK',slot16:slot,
    md5_match: match?{inhex:match.inhex,len:match.len}:null,
    recent_md5_outs: recentMD5.slice(-6).map(x=>x.out)});
  delete chain[tid];
}});
send({t:'info',msg:'combined hook installed'});
