const crypto = require('crypto');
const KEYS = ["30353861636234383562353433333961","31313432616535636535316232326565","31343466626434656537653935323963","34363537356631646537366161636663","34656238373161363563653430393438","36343930353632646233663265303466","38626531373137343338383534633730","62333764366661373261646235373932","64313666396430646533656535613963","65306136656537306363346661396638"];
const FILES = {
 "5a78_16": "aa87b8828adc698fe6354c2c9180df52",
 "5bbd_32": "aaefae788585292b0ab00f25e8e45d86b762f60290e55083052833ba1fd30292",
 "b99e_8":  "3eb21c51a821ff4e",
 "db4d_8":  "a0297c40bbc81972",
 "092f_130":"c3b27a642260175cb483156827c01af211c86a2d9924680e2d070a908e07f3fc04aef927b0715e5fa3f350c9b3785236cb79816b41a32965b5e8b13d5e2470b7eff7f5956d0d57ffc615592aa3223aeb8f6bd00fd122fb5d5bfddde5db6cfc055d415fb28a1bb78064ed0d23b999d5fa34427f71a77292272d282901753ce43ba07a",
};
function score(buf){ let p=0; for(const b of buf){ if(b>=0x20&&b<0x7e) p++; } return p/buf.length; }
function pv(buf){ // protobuf-ish: leading small field tags
  if(buf.length<2) return 0; const t=buf[0]; const wt=t&7; const fn=t>>3;
  return (fn>=1&&fn<=20&&(wt===0||wt===2))?1:0;
}
function tryDec(keyBuf, ct, mode, iv){
  try{
    const d=crypto.createDecipheriv(mode, keyBuf, iv);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(ct), d.final()]);
  }catch(e){ return null; }
}
for(const [fn,fhex] of Object.entries(FILES)){
  const full=Buffer.from(fhex,'hex');
  const len=full.length;
  for(const kh of KEYS){
    const key=Buffer.from(kh,'hex');
    const kascii=Buffer.from(kh,'hex').toString('ascii');
    // ECB (needs len%16==0)
    if(len%16===0){
      const pt=tryDec(key,full,'aes-128-ecb',Buffer.alloc(0));
      if(pt){ const s=score(pt); if(s>0.75||pv(pt)) console.log(`[ECB]   ${fn} key=${kascii} score=${s.toFixed(2)} pv=${pv(pt)} pt=${pt.toString('hex').slice(0,48)} | ${JSON.stringify(pt.toString('latin1').slice(0,32))}`); }
      // CBC zero IV
      const pt2=tryDec(key,full,'aes-128-cbc',Buffer.alloc(16));
      if(pt2){ const s=score(pt2); if(s>0.75||pv(pt2)) console.log(`[CBC0]  ${fn} key=${kascii} score=${s.toFixed(2)} pv=${pv(pt2)} pt=${pt2.toString('hex').slice(0,48)} | ${JSON.stringify(pt2.toString('latin1').slice(0,32))}`); }
      // CBC with leading 16 bytes as IV
      if(len>16){
        const iv=full.slice(0,16), body=full.slice(16);
        const pt3=tryDec(key,body,'aes-128-cbc',iv);
        if(pt3){ const s=score(pt3); if(s>0.75||pv(pt3)) console.log(`[CBCiv] ${fn} key=${kascii} score=${s.toFixed(2)} pv=${pv(pt3)} pt=${pt3.toString('hex').slice(0,48)} | ${JSON.stringify(pt3.toString('latin1').slice(0,32))}`); }
      }
    }
    // CTR (keystream) works for any length incl 8B
    for(const ivseed of [Buffer.alloc(16)]){
      const pt=tryDec(key,full,'aes-128-ctr',ivseed);
      if(pt){ const s=score(pt); if(s>0.85) console.log(`[CTR0]  ${fn} key=${kascii} score=${s.toFixed(2)} pt=${pt.toString('hex').slice(0,32)} | ${JSON.stringify(pt.toString('latin1').slice(0,24))}`); }
    }
  }
}
console.log("done");
