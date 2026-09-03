// _compress.js — faithful Node reimplementation of the slot16 producer's Compress() block.
// Mirrors libmetasec_ov.so instructions 0xa0e00..0xa0f9c ONE-STATEMENT-PER-INSTRUCTION, in address order.
// Inputs: 32B state (IV), and 3 schedule tables T0/T1/T2 (64 x uint32 LE each). Output: new 32B state.
// Verified 16/16 by diffing against clean live (iv, tables) -> out captures in _clean2_records.json.
// (NOTE: _dump_records.json is the OLD corrupted capture — Frida x16 clobber, see STATUS 2026-08-27 — do not use.)
'use strict';
const fs = require('fs');

const u32 = x => x >>> 0;
const ror = (x, n) => { n &= 31; return n ? (((x >>> n) | (x << (32 - n))) >>> 0) : (x >>> 0); };

function wordsLE(hex) {           // hex string -> Uint32Array (little-endian 4-byte words)
  const n = hex.length / 8, a = new Uint32Array(n);
  for (let i = 0; i < n; i++) {
    const b = hex.substr(i * 8, 8);
    a[i] = u32(parseInt(b.substr(0,2),16) | (parseInt(b.substr(2,2),16)<<8) |
               (parseInt(b.substr(4,2),16)<<16) | (parseInt(b.substr(6,2),16)<<24));
  }
  return a;
}
function toHexLE(arr) {            // Uint32Array -> hex (little-endian bytes)
  let s = '';
  for (const v of arr) {
    s += ('0'+((v)&0xff).toString(16)).slice(-2) + ('0'+((v>>>8)&0xff).toString(16)).slice(-2)
       + ('0'+((v>>>16)&0xff).toString(16)).slice(-2) + ('0'+((v>>>24)&0xff).toString(16)).slice(-2);
  }
  return s;
}

function compress(ivHex, tablesHex) {
  const IN = wordsLE(ivHex);                       // IN[0..7]
  const T0 = wordsLE(tablesHex.substr(0,512));     // 64 words
  const T1 = wordsLE(tablesHex.substr(512,512));
  const T2 = wordsLE(tablesHex.substr(1024,512));

  // 0xa0e00: load state into named regs
  let w16=IN[0], w17=IN[1], w15=IN[2], w14=IN[3], w13=IN[4], w12=IN[5], w11=IN[6], w8=IN[7];
  let x0=0;
  // working regs (0xa0e20-3c)
  let w4=w16, w21=w8, w5=w11, w23=w12, w25=w13, w22=w14, w20=w15, w24=w17;
  let w1=0, w2=0, w3=0, w26=0, w27=0, w28=0;

  // ---- Loop A (0xa0e40..0xa0ec8): 16 rounds, i=0..15 ----
  while (true) {
    const i = x0;                       // a0e58 x26=x0<<2 ; a0e84 neg w0 uses this i
    w1 = w20;                            // a0e40
    w3 = w25;                            // a0e44
    w25 = u32(w20 ^ w24);               // a0e48
    w20 = ror(w24, 23);                 // a0e4c
    w24 = w4;                           // a0e50
    w2 = w5;                            // a0e54
    w28 = u32(w23 ^ w3);               // a0e5c
    w5 = ror(w23, 13);                 // a0e60
    w23 = u32(w25 ^ w24);              // a0e64
    w22 = u32(w23 + w22);              // a0e68
    w23 = T0[i];                        // a0e6c
    w25 = u32(w28 ^ w2);              // a0e70
    w21 = u32(w25 + w21);             // a0e74
    w25 = T1[i];                        // a0e78
    w26 = T2[i];                        // a0e7c
    w4 = ror(w4, 20);                  // a0e80
    w27 = u32(-x0);                    // a0e84 neg w0
    w23 = ror(w23, w27 & 31);         // a0e88
    w27 = u32(w4 + w3);              // a0e8c
    w23 = u32(w27 + w23);            // a0e90
    w21 = u32(w21 + w26);           // a0e94
    w23 = ror(w23, 25);              // a0e98
    w22 = u32(w22 + w25);           // a0e9c
    w4 = u32(w23 ^ w4);             // a0ea0
    w21 = u32(w21 + w23);           // a0ea4
    x0 = u32(x0 + 1);                // a0ea8
    w4 = u32(w22 + w4);             // a0eac
    w22 = u32(w21 ^ ror(w21, 23));  // a0eb0
    w25 = u32(w22 ^ ror(w21, 15));  // a0eb8
    w21 = w2;                          // a0ebc
    w23 = w3;                          // a0ec0
    w22 = w1;                          // a0ec4
    if (x0 === 0x10) break;            // a0ec8 b.ne
  }

  // ---- Loop B (0xa0ed8..0xa0f6c): 48 rounds, i=16..63 ----
  while (true) {
    const i = x0;                       // a0f00 x27=x0<<2
    w22 = w25;                          // a0ed8
    w21 = w5;                           // a0edc
    w23 = w20;                          // a0ee0
    w5 = u32(w20 | w24);               // a0ee4
    w25 = u32(w20 & w24);              // a0ee8
    w20 = ror(w24, 23);                // a0eec
    w24 = w4;                           // a0ef0
    w26 = u32(w3 & w22);              // a0ef4
    w27 = u32(w21 & (~w22));         // a0ef8 bic
    w26 = u32(w27 | w26);            // a0efc
    w5 = u32(w24 & w5);              // a0f04
    w25 = u32(w5 | w25);            // a0f08
    w5 = ror(w3, 13);                 // a0f0c
    w3 = T0[i];                        // a0f10
    w2 = u32(w26 + w2);             // a0f14
    w26 = T2[i];                       // a0f18
    w4 = ror(w4, 20);                 // a0f1c
    w28 = u32(-x0);                   // a0f20 neg w0
    w1 = u32(w25 + w1);            // a0f24
    w25 = T1[i];                       // a0f28
    w3 = ror(w3, w28 & 31);          // a0f2c
    w27 = u32(w4 + w22);           // a0f30
    w3 = u32(w27 + w3);            // a0f34
    w2 = u32(w2 + w26);           // a0f38
    w3 = ror(w3, 25);               // a0f3c
    w1 = u32(w1 + w25);           // a0f40
    w4 = u32(w3 ^ w4);            // a0f44
    w2 = u32(w2 + w3);           // a0f48
    x0 = u32(x0 + 1);              // a0f4c
    w4 = u32(w1 + w4);           // a0f50
    w1 = u32(w2 ^ ror(w2, 23));  // a0f54
    w25 = u32(w1 ^ ror(w2, 15)); // a0f5c
    w2 = w21;                         // a0f60
    w3 = w22;                         // a0f64
    w1 = w23;                         // a0f68
    if (x0 === 0x40) break;           // a0f6c b.ne
  }

  // ---- whitening (0xa0f70..0xa0f8c): feed-forward XOR with original IN ----
  w16 = u32(w4 ^ w16);
  w17 = u32(w24 ^ w17);
  w15 = u32(w20 ^ w15);
  w14 = u32(w23 ^ w14);
  w13 = u32(w25 ^ w13);
  w12 = u32(w22 ^ w12);
  w11 = u32(w5 ^ w11);
  w8  = u32(w21 ^ w8);

  // ---- store order (0xa0f90..0xa0f9c) ----
  return new Uint32Array([w16, w17, w15, w14, w13, w12, w11, w8]);
}

// ---- verify against captures ----
const recs = JSON.parse(fs.readFileSync(process.argv[2] || '_clean2_records.json', 'utf8'));
let pass = 0;
for (const r of recs) {
  const got = toHexLE(compress(r.iv, r.tables));
  const ok = got === r.out;
  if (ok) pass++;
  console.log(`  #${String(r.n).padStart(2)}: ${ok ? 'PASS' : 'FAIL'}  got=${got}`);
  if (!ok) console.log(`         exp=${r.out}`);
}
console.log(`\n== ${pass}/${recs.length} PASS ==`);
module.exports = { compress, wordsLE, toHexLE };
