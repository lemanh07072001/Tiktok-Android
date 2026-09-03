'use strict';
// v2: adds (a) key=H(keyname) family [forge-offline test], (b) prepended-nonce structs,
// (c) AES-256 from H(keyname)[:32], (d) rigorous scoring on msp/mss only.
const crypto=require('crypto'), fs=require('fs');
const H=h=>Buffer.from(h,'hex');
const md=(a,s)=>crypto.createHash(a).update(s).digest();

const CAP_KEYS={
  K1_b114:H('b114249b7bed9d2691d70c60d69f9c4f'),
  K2_8252:H('8252970d959b06db102e17d85c0ec1af'),
  K3_b8d7:H('b8d72ddec05142948bbf2dc81d63759c'),
};
const IVs=[H('4d207ea37a419f7d622f81c6a2f53594'),H('d6c3969582f9ac5313d39c180b54a2bc'),Buffer.alloc(16)];

const FILES=[
  {n:'msp', keyname:'sdi_v2',        fp:'_msdump_live/.msp_092fde7a53a0274594af0984c7830fc0c13dc8bd'},
  {n:'mss', keyname:'mssdk_setting', fp:'_msdump_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d'},
];

// key candidates for a given keyname (forge-offline hypothesis)
function hkeys(kn){
  const salts=['', 'metasec','mssdk','ov','ttmssdk','com.zhiliaoapp.musically'];
  const out={};
  for(const s of salts){
    const m=kn+s;
    out[`md5(${kn}|${s})`]=md('md5',m);                    // 16B
    out[`sha1_16(${kn}|${s})`]=md('sha1',m).subarray(0,16);// 16B
    out[`sha256_16(${kn}|${s})`]=md('sha256',m).subarray(0,16);
    out[`sha256_32(${kn}|${s})`]=md('sha256',m);           // 32B -> AES-256
  }
  return out;
}
function score(pt){
  let pr=0; for(const b of pt) if((b>=32&&b<=126)||b===9||b===10||b===13)pr++;
  pr/=pt.length;
  // consecutive protobuf fields
  let proto=0,i=0,ok=0;
  while(i<pt.length&&i<40){const t=pt[i],wt=t&7,fn=t>>3; if(fn>=1&&fn<=40&&(wt===0||wt===2||wt===5||wt===1)){ok++; if(wt===2){const ln=pt[i+1]; if(ln==null||i+2+ln>pt.length){break} i+=2+ln}else if(wt===0){i+=2}else if(wt===5){i+=5}else{i+=9}}else break;}
  proto=ok;
  const gz = pt[0]===0x1f&&pt[1]===0x8b;
  const json = pt[0]===0x7b||pt[0]===0x5b;
  return {pr,proto,gz,json,good:(pr>0.85||proto>=4||gz||json)};
}
function tryStream(mode,key,iv,ct){ try{const d=crypto.createDecipheriv(mode,key,iv);return Buffer.concat([d.update(ct),d.final()]);}catch(e){return null} }
function tryGCM(key,nonce,ct,tag,aad){ try{const d=crypto.createDecipheriv(key.length===32?'aes-256-gcm':'aes-128-gcm',key,nonce,{authTagLength:16}); if(aad)d.setAAD(aad); d.setAuthTag(tag); return Buffer.concat([d.update(ct),d.final()]);}catch(e){return null} }

let hits=[], gcmHits=[];
for(const F of FILES){
  const data=fs.readFileSync(F.fp);
  const keyset={...CAP_KEYS, ...hkeys(F.keyname)};
  for(const [kn,key] of Object.entries(keyset)){
    const smode = key.length===32?['aes-256-ctr','aes-256-ofb','aes-256-cfb']:['aes-128-ctr','aes-128-ofb','aes-128-cfb'];
    // structures
    const structs=[
      {tag:'whole', ct:data, ivs:IVs},                                  // whole file = ciphertext
      {tag:'pre16', ct:data.subarray(16), ivs:[data.subarray(0,16)]},   // [IV16][ct]
      {tag:'pre12', ct:data.subarray(12), ivs:[Buffer.concat([data.subarray(0,12),Buffer.alloc(4)])]},
    ];
    for(const st of structs){
      for(const iv of st.ivs){
        if(iv.length!==16) continue;
        for(const mode of smode){
          const pt=tryStream(mode,key,iv,st.ct); if(!pt||!pt.length)continue;
          const s=score(pt);
          if(s.good) hits.push({file:F.n,key:kn,mode,struct:st.tag,pr:s.pr.toFixed(2),proto:s.proto,gz:s.gz,json:s.json,head:pt.subarray(0,32).toString('hex'),ascii:pt.subarray(0,32).toString('latin1').replace(/[^\x20-\x7e]/g,'.')});
        }
      }
    }
    // GCM structures: ct||tag  and  [nonce12]ct||tag
    if(data.length>=17){
      const A={ct:data.subarray(0,data.length-16),tag:data.subarray(data.length-16),nonces:[...IVs,data.subarray(0,12)]};
      const B={ct:data.subarray(12,data.length-16),tag:data.subarray(data.length-16),nonces:[data.subarray(0,12)]};
      for(const G of [A,B]){
        for(const nonce of G.nonces){ for(const aad of [null,Buffer.from(F.keyname)]){
          const pt=tryGCM(key,nonce,G.ct,G.tag,aad); if(pt!==null){ gcmHits.push({file:F.n,key:kn,nonce:nonce.toString('hex'),aad:aad?aad.toString():'-',ptLen:pt.length,head:pt.subarray(0,32).toString('hex')}); }
        }}
      }
    }
  }
}
console.log('=== GCM TAG-VERIFY HITS ==='); console.log(gcmHits.length?JSON.stringify(gcmHits,null,1):'  (none)');
console.log('\n=== STREAM PLAUSIBLE HITS (msp/mss, rigorous) ===');
console.log(hits.length?JSON.stringify(hits.slice(0,25),null,1):'  (none — không key/mode/struct nào cho plaintext hợp lý)');
console.log('\ncounts: GCM='+gcmHits.length+' STREAM='+hits.length);
