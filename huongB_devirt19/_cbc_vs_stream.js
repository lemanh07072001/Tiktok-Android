const fs=require('fs');
const F=[ '_msdump/msp_092f.bin','_msdump_live/msp_092f.bin','_msdump_live2/msp_092f.bin' ];
const B=F.map(f=>fs.readFileSync(f));
console.log('sizes', B.map(b=>b.length));
function xormap(a,b,label){
  const n=Math.min(a.length,b.length);
  let diff=0; const rows=[];
  for(let r=0;r<n;r+=16){
    let line=''; let hexA='';
    for(let i=r;i<r+16&&i<n;i++){const d=a[i]^b[i]; if(d)diff++; line+= d? 'X':'.'; hexA+=(a[i]^b[i]).toString(16).padStart(2,'0');}
    rows.push(String(r).padStart(3)+': '+line+'   '+hexA);
  }
  console.log(`\n=== ${label}  (diffbytes=${diff}/${n}, ${(100*diff/n).toFixed(1)}%) ===`);
  console.log(rows.join('\n'));
  // contiguity: after first diff, fraction of bytes that differ
  let first=-1,last=-1,inRegionSame=0,inRegionTot=0;
  for(let i=0;i<n;i++){if(a[i]^b[i]){if(first<0)first=i;last=i;}}
  for(let i=first;i<=last&&first>=0;i++){inRegionTot++; if(!(a[i]^b[i]))inRegionSame++;}
  console.log(`first-diff=${first} last-diff=${last} region-len=${inRegionTot} same-within-region=${inRegionSame} (${first>=0?(100*inRegionSame/inRegionTot).toFixed(1):'-'}% holes)`);
  console.log(`>>> ${inRegionSame===0?'CONTIGUOUS (CBC avalanche-like)':'SPARSE/holey (stream-XOR-like)'}`);
}
xormap(B[0],B[1],'v0^v1');
xormap(B[0],B[2],'v0^v2');
xormap(B[1],B[2],'v1^v2');
