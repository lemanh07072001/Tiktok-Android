'use strict';
const fs=require('fs');
const F=[
 {n:'msf3',fp:'_msdump_live/.msf3_5a78573b16f3ea4c2cd50666201214b78de95b0e'},
 {n:'msp', fp:'_msdump_live/.msp_092fde7a53a0274594af0984c7830fc0c13dc8bd'},
 {n:'mss', fp:'_msdump_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d'},
];
function ent(b){const c=new Array(256).fill(0);for(const x of b)c[x]++;let e=0;for(const n of c){if(!n)continue;const p=n/b.length;e-=p*Math.log2(p);}return e;}
function dump(b){let o='';for(let i=0;i<b.length;i+=16){const s=b.subarray(i,i+16);let h=[...s].map(x=>x.toString(16).padStart(2,'0')).join(' ');let a=[...s].map(x=>x>=32&&x<=126?String.fromCharCode(x):'.').join('');o+=String(i).padStart(4,' ')+'  '+h.padEnd(48,' ')+'  |'+a+'|\n';}return o;}
for(const f of F){
  const b=fs.readFileSync(f.fp);
  console.log(`\n===== ${f.n} (${b.length}B) entropy=${ent(b).toFixed(3)} bits/byte =====`);
  // 16-block repeat check
  const seen={},rep=[];
  for(let i=0;i+16<=b.length;i+=16){const k=b.subarray(i,i+16).toString('hex');if(seen[k]!=null)rep.push([seen[k],i]);seen[k]=i;}
  console.log('16B-block repeats:',rep.length?JSON.stringify(rep):'none');
  // length divisibility
  console.log('len%16=',b.length%16,' len%12=',b.length%12,' (len-16)%16=',(b.length-16)%16);
  console.log(dump(b));
}
