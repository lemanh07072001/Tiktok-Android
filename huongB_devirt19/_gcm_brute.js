'use strict';
// OFFLINE store-decrypt brute. GCM tag-verify = definitive. Stream modes = plausibility.
// Deliverable test = DIFF vs ground-truth _msdump_live/. No phone.
const crypto = require('crypto'), fs = require('fs');

const H = h => Buffer.from(h, 'hex');
const KEYS = {
  K1_req_b114: 'b114249b7bed9d2691d70c60d69f9c4f',
  K2_req_8252: '8252970d959b06db102e17d85c0ec1af',
  K3_store_b8d7: 'b8d72ddec05142948bbf2dc81d63759c',
};
const IVs = {
  IVa: '4d207ea37a419f7d622f81c6a2f53594',
  IVb: 'd6c3969582f9ac5313d39c180b54a2bc',
};
function bswap16(hex){ // byteswap each 32-bit word (schedule<->key endian)
  const b=H(hex), o=Buffer.alloc(b.length);
  for(let i=0;i<b.length;i+=4){ o[i]=b[i+3];o[i+1]=b[i+2];o[i+2]=b[i+1];o[i+3]=b[i]; }
  return o.toString('hex');
}
const FILES = {
  msf3: '_msdump_live/.msf3_5a78573b16f3ea4c2cd50666201214b78de95b0e',
  msp:  '_msdump_live/.msp_092fde7a53a0274594af0984c7830fc0c13dc8bd',
  mss:  '_msdump_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d',
};

// nonce candidates (12 & 16B, raw & byteswapped, zeros)
function nonces(){
  const out={};
  for(const [n,h] of Object.entries(IVs)){
    out[n+'_16']=H(h);
    out[n+'_12']=H(h).subarray(0,12);
    out[n+'_bsw16']=H(bswap16(h));
    out[n+'_bsw12']=H(bswap16(h)).subarray(0,12);
  }
  out.zero12=Buffer.alloc(12); out.zero16=Buffer.alloc(16);
  return out;
}
const NONCES = nonces();

function entropy(buf){
  const f=new Array(256).fill(0); for(const b of buf)f[b]++;
  let e=0; for(const c of f){ if(c){const p=c/buf.length; e-=p*Math.log2(p);} } return e;
}
function printableRatio(buf){ let p=0; for(const b of buf) if(b>=9&&b<=126)p++; return p/buf.length; }
function protoish(buf){ // crude: valid field-tag wire types at start
  if(!buf.length) return false;
  const wt=buf[0]&7, fn=buf[0]>>3;
  return (wt<=5 && wt!==3 && wt!==4 && fn>=1 && fn<=32);
}

let GCM_HITS=[], STREAM_HITS=[];
for(const [fn, fp] of Object.entries(FILES)){
  const data = fs.readFileSync(fp);
  for(const [kn, kh] of Object.entries(KEYS)){
    const key = H(kh); // 16B -> AES-128
    // also try byteswapped key form
    for(const [ktag, kb] of [['',key],['bsw',H(bswap16(kh))]]){
      // ---- GCM: file = ct||tag(16) ----
      if(data.length>=16){
        const ct=data.subarray(0,data.length-16), tag=data.subarray(data.length-16);
        for(const [nn, nonce] of Object.entries(NONCES)){
          for(const aad of [null, Buffer.from(fn), Buffer.from('')]){
            try{
              const d=crypto.createDecipheriv('aes-128-gcm', kb, nonce, {authTagLength:16});
              if(aad) d.setAAD(aad);
              d.setAuthTag(tag);
              const pt=Buffer.concat([d.update(ct), d.final()]); // throws on tag fail
              GCM_HITS.push({file:fn,key:kn+ktag,nonce:nn,aad:aad?aad.toString():'-',ptHex:pt.subarray(0,32).toString('hex'),ptLen:pt.length});
            }catch(e){}
          }
        }
      }
      // ---- STREAM (CTR/OFB/CFB): whole file = ct, score output ----
      for(const mode of ['aes-128-ctr','aes-128-ofb','aes-128-cfb']){
        for(const [nn, nonce] of Object.entries(NONCES)){
          if(nonce.length!==16) continue; // stream modes need 16B IV
          try{
            const d=crypto.createDecipheriv(mode, kb, nonce);
            const pt=Buffer.concat([d.update(data), d.final()]);
            const ent=entropy(pt), pr=printableRatio(pt), pi=protoish(pt);
            const score=(pr>0.85?2:0)+(ent<6.0?2:0)+(pi?1:0);
            if(score>=3) STREAM_HITS.push({file:fn,mode,key:kn+ktag,nonce:nn,ent:ent.toFixed(2),pr:pr.toFixed(2),proto:pi,head:pt.subarray(0,24).toString('hex')});
          }catch(e){}
        }
      }
    }
  }
}
console.log('=== GCM TAG-VERIFY HITS (định đoạt) ===');
console.log(GCM_HITS.length? JSON.stringify(GCM_HITS,null,1) : '  (none — không phải GCM với key/nonce đã biết)');
console.log('\n=== STREAM PLAUSIBILITY HITS (score>=3) ===');
console.log(STREAM_HITS.length? JSON.stringify(STREAM_HITS.slice(0,20),null,1) : '  (none — output nhiễu, không giống config/proto)');
console.log('\ncounts: GCM='+GCM_HITS.length+' STREAM='+STREAM_HITS.length);
