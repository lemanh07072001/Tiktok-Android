// _sm3.js — pure-Node STANDARD SM3, proven equal to the libmetasec slot16 producer.
// Discovery (2026-08-27): the "producer" at libmetasec_ov.so 0xa0748 is standard SM3 (GB/T 32905-2016):
//   IV     = SM3 IV 7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e (stored byteswapped)
//   T0     = SM3 round constant Tj (0x79cc4519 j<16, 0x7a879d8a j>=16), rotated <<<j per round
//   T2     = SM3 message schedule W[0..67]           (verified 8/8 vs _marshal_records.json)
//   T1     = SM3 W'[j] = W[j] ^ W[j+4]               (verified 8/8)
//   Compress = SM3 compression (Loop A rounds 0-15 FF0/GG0=XOR, Loop B 16-63 FF1=MAJ/GG1=CH)
// This file is the clean spec-level implementation. compressBlock() is proven 16/16 against
// _clean2_records.json via _sm3_verify.js (same numbers as the instruction-mirror _compress.js).
'use strict';

const u32 = x => x >>> 0;
const rol = (x, n) => { n &= 31; return n ? (((x << n) | (x >>> (32 - n))) >>> 0) : (x >>> 0); };

// SM3 boolean/permutation functions
const FF = (x, y, z, j) => j < 16 ? u32(x ^ y ^ z) : u32((x & y) | (x & z) | (y & z));
const GG = (x, y, z, j) => j < 16 ? u32(x ^ y ^ z) : u32((x & y) | (~x & z));
const P0 = x => u32(x ^ rol(x, 9)  ^ rol(x, 17));
const P1 = x => u32(x ^ rol(x, 15) ^ rol(x, 23));
const Tj = j => j < 16 ? 0x79cc4519 : 0x7a879d8a;

const IV = [0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e];

// One SM3 compression: state V (8 big-endian words) + 64-byte block B -> new V. Standard spec form.
function compressBlock(V, B /* Uint8Array(64) or 16 BE words */) {
  const W = new Array(68), Wp = new Array(64);
  const words = (B instanceof Uint8Array)
    ? Array.from({length:16}, (_,i)=>u32((B[i*4]<<24)|(B[i*4+1]<<16)|(B[i*4+2]<<8)|B[i*4+3]))
    : B.slice(0,16);
  for (let i = 0; i < 16; i++) W[i] = words[i];
  for (let j = 16; j < 68; j++)
    W[j] = u32(P1(u32(W[j-16] ^ W[j-9] ^ rol(W[j-3],15))) ^ rol(W[j-13],7) ^ W[j-6]);
  for (let j = 0; j < 64; j++) Wp[j] = u32(W[j] ^ W[j+4]);

  let [A,Bx,C,D,E,F,G,H] = V;
  for (let j = 0; j < 64; j++) {
    const SS1 = rol(u32(rol(A,12) + E + rol(Tj(j), j % 32)), 7);
    const SS2 = u32(SS1 ^ rol(A,12));
    const TT1 = u32(FF(A,Bx,C,j) + D + SS2 + Wp[j]);
    const TT2 = u32(GG(E,F,G,j) + H + SS1 + W[j]);
    D = C; C = rol(Bx,9); Bx = A; A = TT1;
    H = G; G = rol(F,19); F = E; E = P0(TT2);
  }
  return [u32(A^V[0]),u32(Bx^V[1]),u32(C^V[2]),u32(D^V[3]),u32(E^V[4]),u32(F^V[5]),u32(G^V[6]),u32(H^V[7])];
}

// SM3 padding: append 0x80, zero-fill, then 64-bit big-endian bit length.
function pad(msg /* Uint8Array */) {
  const bitLen = msg.length * 8;
  let padLen = (56 - (msg.length + 1) % 64 + 64) % 64;
  const out = new Uint8Array(msg.length + 1 + padLen + 8);
  out.set(msg, 0); out[msg.length] = 0x80;
  // 64-bit big-endian length in the last 8 bytes (JS: high 32 bits from /2^32)
  const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  const dv = new DataView(out.buffer);
  dv.setUint32(out.length - 8, hi); dv.setUint32(out.length - 4, lo);
  return out;
}

function sm3(msg /* Uint8Array */) {
  const m = pad(msg);
  let V = IV.slice();
  for (let off = 0; off < m.length; off += 64) V = compressBlock(V, m.subarray(off, off+64));
  return V;                                  // 8 big-endian words (digest)
}

const digestHexBE = V => V.map(w => ('0000000'+(w>>>0).toString(16)).slice(-8)).join('');

module.exports = { compressBlock, pad, sm3, digestHexBE, IV, u32, rol };

// ---- self-test: run `node _sm3.js` — three independent ground-truth checks ----
if (require.main === module) {
  const fs = require('fs');
  const H = '/Users/lemanh/Documents/Tiktok-Android/huongB_devirt19';
  const bytesFromHex = h => { const u = new Uint8Array(h.length/2); for (let i=0;i<u.length;i++) u[i]=parseInt(h.substr(i*2,2),16); return u; };
  const wordsLE = h => { const n=h.length/8,a=[]; for(let i=0;i<n;i++){const b=h.substr(i*8,8);
    a.push(u32(parseInt(b.substr(0,2),16)|(parseInt(b.substr(2,2),16)<<8)|(parseInt(b.substr(4,2),16)<<16)|(parseInt(b.substr(6,2),16)<<24)));} return a; };
  const outHexLE = V => V.map(w=>{const b=x=>('0'+((w>>>x)&0xff).toString(16)).slice(-2);return b(0)+b(8)+b(16)+b(24);}).join('');
  let allOk = true;

  // (1) standard SM3 test vector
  const abc = digestHexBE(sm3(new Uint8Array([0x61,0x62,0x63])));
  const okAbc = abc === '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';
  console.log(`(1) SM3("abc") standard vector: ${okAbc?'PASS':'FAIL '+abc}`); allOk &&= okAbc;

  // (2) compressBlock vs real device iv/block/out captures (schedule built from scratch)
  for (const f of ['_clean2_records.json','_marshal_records.json']) {
    const recs = JSON.parse(fs.readFileSync(`${H}/${f}`,'utf8')); let pass=0,tot=0;
    for (const r of recs) {
      if (!r.iv||!r.out) continue;
      const block = r.msg ? bytesFromHex(r.msg.substr(0,128))
        : (()=>{const t=wordsLE(r.tables.substr(1024,512)).slice(0,16),b=new Uint8Array(64);
             for(let i=0;i<16;i++){b[i*4]=(t[i]>>>24)&255;b[i*4+1]=(t[i]>>>16)&255;b[i*4+2]=(t[i]>>>8)&255;b[i*4+3]=t[i]&255;}return b;})();
      if (outHexLE(compressBlock(wordsLE(r.iv),block))===r.out) pass++; tot++;
    }
    console.log(`(2) compressBlock vs ${f}: ${pass}/${tot} ${pass===tot?'PASS':'FAIL'}`); allOk &&= (pass===tot);
  }

  // (3) #19 report hash SM3(query||slot16||'0') vs device digest
  const T = JSON.parse(fs.readFileSync(`${H}/ground-truth/hash19_nonzero_tuples.json`,'utf8')); let p=0;
  for (const t of T) {
    const qb=new TextEncoder().encode(t.query), sb=bytesFromHex(t.slot16), zb=new TextEncoder().encode('0');
    const m=new Uint8Array(qb.length+sb.length+1); m.set(qb,0); m.set(sb,qb.length); m.set(zb,qb.length+sb.length);
    if (digestHexBE(sm3(m))===t.digest_std) p++;
  }
  console.log(`(3) #19 SM3(query||slot16||'0'): ${p}/${T.length} ${p===T.length?'PASS':'FAIL'}`); allOk &&= (p===T.length);

  console.log(`\n== ${allOk?'ALL PASS — producer == standard SM3, pure-Node':'FAIL'} ==`);
  process.exit(allOk?0:1);
}
