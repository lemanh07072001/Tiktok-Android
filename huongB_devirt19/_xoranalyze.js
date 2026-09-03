const fs=require('fs'),cp=require('child_process');
function readhex(path){ return fs.readFileSync(path); }
function find(dir,frag){ try{ const out=cp.execSync(`/usr/bin/find ${dir} -maxdepth 1 -name '*${frag}*'`).toString().trim().split('\n').filter(Boolean); return out[0]; }catch(e){ return null; } }
function xorReport(name, frag, dirs){
  const bufs=dirs.map(d=>{const f=find(d,frag); return f&&fs.existsSync(f)?fs.readFileSync(f):null;}).filter(Boolean);
  if(bufs.length<2){ console.log(`${name}: <2 files`); return; }
  console.log(`\n### ${name} (${bufs.length} versions, sizes ${bufs.map(b=>b.length).join('/')})`);
  // pairwise XOR of the shortest common length among first two
  for(let a=0;a<bufs.length-1;a++){
    const x=bufs[a], y=bufs[a+1]; const n=Math.min(x.length,y.length);
    let diff=0, firstDiffs=[];
    for(let i=0;i<n;i++){ const d=x[i]^y[i]; if(d){ diff++; if(firstDiffs.length<12) firstDiffs.push(i+':'+d.toString(16)); } }
    console.log(`  v${a}^v${a+1}: len=${n} diffBytes=${diff} (${(100*diff/n).toFixed(0)}%) firstDiffs=[${firstDiffs.join(' ')}]`);
  }
}
xorReport('msp_092f','092f',['_msdump','_msdump_live','_msdump_live2']);
xorReport('msp_589c','589c',['_msdump','_msdump_live','_msdump_live2']);
xorReport('mss_9b8e','9b8e',['_msdump','_msdump_live','_msdump_live2','_msdump_live3']);
xorReport('msf3_5a78','5a78',['_msdump_live','_msdump_live2']);
// cross-store: do mss and msp share keystream? xor first N bytes
const mss=readhex(find('_msdump_live3','9b8e')), msp=readhex(find('_msdump_live3','589c'));
let n=Math.min(mss.length,msp.length),d=0; for(let i=0;i<n;i++) if(mss[i]^msp[i]) d++;
console.log(`\ncross mss^msp589c: len=${n} diff=${d} (${(100*d/n).toFixed(0)}%) -> ${d>n*0.9?'independent keystreams':'possible shared'}`);
