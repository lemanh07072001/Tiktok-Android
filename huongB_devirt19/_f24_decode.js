// _f24_decode.js — decode lai #24/dyn_seed blob (2026-09-04, claude)
// Buoc 1: differential 5 mau (prefix matrix). Buoc 2: structure scan mau day du.
// Buoc 3: search timestamp/device-id embedded. Buoc 4: decrypt matrix (AES/MD5/SM3 keys).
'use strict';
const crypto = require('crypto');
const { sm3, digestHexBE } = require('./_sm3.js');

const S = {
  S1_full_7678616678053643790: 'MDGkEprSrHADIDZ6yWtkztTtnLIoFXUlUzcso/xeHUnQLB3XQDc6HAV+FRzlNQOm2ekPLgHBxRSevg7OUKLwWVSQx2CKVuYBe4tnmkAW7TRq/cERFu7jpn8VOSyBvYKYAfE=',
  S2_phoneGenuine_7664923: 'MDGnGpXSpHsBJj8xg2wyzoO2',   // note 30 (truncated 24ch)
  S3_storeDriven_7664923:   'MDGnGpXSpHsBJj8x0TFixYfj',   // note 46 _ds7664922 (truncated)
  S4_ds7666:                'MDGlHJrUpXIAIT18yWxjztXj',   // note 46 (truncated)
  S5_stubBuilt:             'MDGkHJnbrHMFJzt4yTwzldTh',   // note 32 (truncated)
};
const DEV = { S1: '7678616678053643790', S2: '7664923887225882119?', S3: '7664923887225882119?', S4: '7666xxx', S5: 'stub' };
const SEC = {
  device_id: '7678616678053643790',
  install_id: '7679520991450973970',
  rtk2_ms_hex: '65d4a4323c59fd1a8382a8380032f95e14a3d0366ddb8c20846d',
  kiid: 'ef86fe33-0264-4b06-ba72-813be3d22158',
  fltk_ms: '1787822601249',
  dyn_last_update_time: 1788177640,
  server_tsp_diff: 1030,
  signkey32_hex: 'c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163',
};

const md5b = m => crypto.createHash('md5').update(m).digest();
const sha256b = m => crypto.createHash('sha256').update(m).digest();
const sm3b = m => Buffer.from(digestHexBE(sm3(Buffer.isBuffer(m) ? new Uint8Array(m) : new Uint8Array(Buffer.from(m)))), 'hex');
const hex = b => Buffer.from(b).toString('hex');
const dec = s => Buffer.from(s, 'base64');

console.log('== BUOC 1: differential 5 mau ==');
const B = {};
for (const [k, v] of Object.entries(S)) {
  const d = dec(v);
  B[k.slice(0, 2)] = d;
  console.log(`${k.slice(0, 2)} len=${d.length}B b64len=${v.length}${v.endsWith('=') ? ' (co padding)' : ''} : ${hex(d)}`);
}
const keys = Object.keys(B);
console.log('\ncommon-prefix (bytes) between pairs:');
for (let i = 0; i < keys.length; i++) for (let j = i + 1; j < keys.length; j++) {
  const a = B[keys[i]], b = B[keys[j]];
  let n = 0; while (n < Math.min(a.length, b.length) && a[n] === b[n]) n++;
  const tag = (keys[i] === keys[j]) ? '' : '';
  const sameDev = (['S2','S3'].includes(keys[i]) && ['S2','S3'].includes(keys[j])) ? '  <== CUNG DEVICE' : '';
  console.log(`  ${keys[i]}~${keys[j]}: ${n} bytes${sameDev}`);
}

console.log('\n== BUOC 2: structure scan mau day du S1 (98B) ==');
const F = B.S1;
console.log('byte[0..1] =', hex(F.slice(0, 2)), '= ASCII "' + F.slice(0, 2).toString() + '"');
console.log('byte[2] =', F[2].toString(16).padStart(2, '0'), '(bit pattern', F[2].toString(2).padStart(8, '0') + ')');
console.log('tail sau 2B header =', F.length - 2, 'B', ((F.length - 2) % 16 === 0) ? '(= ' + ((F.length - 2) / 16) + ' khoi AES DUNG CHAN)' : '(KHONG block-aligned)');
let printable = 0; for (const c of F) if (c >= 0x20 && c < 0x7f) printable++;
console.log('printable ratio toan blob =', (printable / F.length).toFixed(2));
const entropy = buf => {
  if (!buf.length) return 0;
  const f = new Array(256).fill(0); for (const c of buf) f[c]++;
  let e = 0; for (const x of f) if (x) { const p = x / buf.length; e -= p * Math.log2(p); }
  return e;
};
console.log('entropy tung vuc 16B:', Array.from({ length: 6 }, (_, i) => entropy(F.slice(2 + i * 16, 2 + (i + 1) * 16))).map(e => e.toFixed(2)).join(' '));

console.log('\n== BUOC 3: search gia tri embedded trong S1 ==');
const found = [];
// timestamp unix-seconds / milliseconds trong cua so 2026-08-15..2026-09-10
const LO = 1786704000, HI = 1789060800; // 2026-08-15 .. 2026-09-10 (giay)
for (let i = 0; i + 4 <= F.length; i++) for (const le of [false, true]) {
  const v = le ? F.readUInt32LE(i) : F.readUInt32BE(i);
  if (v >= LO && v <= HI) found.push(`  offset ${i} u32${le ? 'LE' : 'BE'} = ${v} (= ${new Date(v * 1000).toISOString().slice(0, 16)})`);
}
// milliseconds 6-byte BE (1787e12..1789e12)
for (let i = 0; i + 6 <= F.length; i++) {
  const v = Number(BigInt('0x' + hex(F.slice(i, i + 6))));
  if (v >= 1786704000000 && v <= 1789060800000) found.push(`  offset ${i} u48BE = ${v} ms (${new Date(v).toISOString().slice(0, 16)})`);
}
// device_id / install_id: ascii, u64 BE/LE
for (const [nm, id] of [['device_id', SEC.device_id], ['install_id', SEC.install_id]]) {
  if (F.toString('latin1').includes(id)) found.push(`  ${nm} ASCII xuat hien!`);
  const big = BigInt(id);
  for (const le of [false, true]) {
    const b8 = Buffer.alloc(8); le ? b8.writeBigUInt64LE(big) : b8.writeBigUInt64BE(big);
    if (F.indexOf(b8) >= 0) found.push(`  ${nm} u64${le ? 'LE' : 'BE'} @ offset ${F.indexOf(b8)}!`);
  }
  const asBcd = Buffer.from(id.split('').map(d => parseInt(d, 10) | 0xf0)); // BCD-ish? skip if none
}
// kiid
if (F.toString('latin1').includes(SEC.kiid)) found.push('  kiid ASCII xuat hien!');
console.log(found.length ? found.join('\n') : '  (khong tim thay timestamp/device-id/kiid o bat ky encoding nao)');

console.log('\n== BUOC 4: decrypt matrix tren tail 96B ==');
const TAIL = F.slice(2);
const km = {
  'SIGN_KEY32': Buffer.from(SEC.signkey32_hex, 'hex'),
  'SIGN_KEY16(first)': Buffer.from(SEC.signkey32_hex.slice(0, 32), 'hex'),
  'md5(device_id)': md5b(SEC.device_id),
  'md5(rtk2_ms bytes)': md5b(Buffer.from(SEC.rtk2_ms_hex, 'hex')),
  'md5(rtk2_ms ascii)': md5b(SEC.rtk2_ms_hex),
  'md5(kiid)': md5b(SEC.kiid),
  'md5(dyn_seed b64)': md5b(S.S1_full_7678616678053643790),
  'sm3(device_id)': sm3b(SEC.device_id),
  'sm3(rtk2_ms ascii)': sm3b(SEC.rtk2_ms_hex),
  'sha256(device_id)': sha256b(SEC.device_id),
  'rtk2_ms[0:16]': Buffer.from(SEC.rtk2_ms_hex.slice(0, 32), 'hex'),
  'rtk2_ms(full28)': Buffer.from(SEC.rtk2_ms_hex, 'hex'),
};
const score = buf => {
  if (!buf || !buf.length) return 0;
  let p = 0; for (const c of buf) if (c >= 0x20 && c < 0x7f) p++;
  let pb = 0; // protobuf-ish: field tags hop le
  for (let i = 0; i + 1 < buf.length;) {
    const tag = buf[i], wt = tag & 7, fn = tag >> 3;
    if (fn < 1 || fn > 40 || (wt !== 0 && wt !== 1 && wt !== 2 && wt !== 5)) break;
    if (wt === 2) { const l = buf[i + 1]; if (i + 2 + l > buf.length) break; i += 2 + l; }
    else if (wt === 0) { let j = i + 1; while (j < buf.length && buf[j] & 0x80) j++; i = j + 1; }
    else i += wt === 1 ? 9 : wt === 5 ? 5 : 2;
    pb = i;
  }
  return p / buf.length + (pb >= buf.length - 2 ? 1 : 0);
};
let hits = [];
for (const [kn, kb] of Object.entries(km)) {
  const variants = [];
  const k16 = kb.length >= 16 ? kb.slice(0, 16) : null;
  const k32 = kb.length >= 32 ? kb.slice(0, 32) : null;
  if (k16) { variants.push(['AES-128-ECB', k16, null]); variants.push(['AES-128-CBC/iv0', k16, Buffer.alloc(16)]); }
  if (k32) { variants.push(['AES-256-ECB', k32, null]); variants.push(['AES-256-CBC/iv0', k32, Buffer.alloc(16)]); }
  variants.push(['AES-128-CBC/iv=tail[0:16],ct=tail[16:96]', k16 || kb.slice(0, 16), 'selfiv']);
  for (const [vn, k, iv] of variants) {
    if (!k || k.length < 16) continue;
    let ct = TAIL, IV = null;
    if (iv === 'selfiv') { IV = TAIL.slice(0, 16); ct = TAIL.slice(16); } else IV = iv;
    try {
      const d = crypto.createDecipheriv(vn.split('/')[0].replace('-CBC/iv0', '-CBC').replace('-CBC/iv', '-CBC'), k, vn.includes('ECB') ? null : IV);
      const pt = Buffer.concat([d.update(ct), d.final()]);
      const sc = score(pt);
      if (sc > 0.85) hits.push(`  ??? ${kn} / ${vn}: score=${sc.toFixed(2)} pt[:24]=${hex(pt.slice(0, 24))}`);
    } catch (e) { /* key len sai cho cipher -> skip */ }
  }
  // XOR keystream: md5-chain va sm3-chain
  for (const gen of ['md5', 'sm3']) {
    let ks = Buffer.alloc(0), ctr = 0;
    while (ks.length < TAIL.length) {
      const blk = gen === 'md5' ? md5b(Buffer.concat([kb, Buffer.from([ctr++])])) : sm3b(Buffer.concat([kb, Buffer.from([ctr++])]));
      ks = Buffer.concat([ks, blk]);
    }
    const pt = Buffer.from(TAIL.map((c, i) => c ^ ks[i]));
    const sc = score(pt);
    if (sc > 0.85) hits.push(`  ??? ${kn} / XOR-${gen}-chain: score=${sc.toFixed(2)} pt[:24]=${hex(pt.slice(0, 24))}`);
  }
}
console.log(hits.length ? hits.join('\n') : '  (KHONG co candidate nao vuot nguong plausible — 12 key-material x AES{128,256}x{ECB,CBC} x XOR{md5,sm3}-chain = 0 hit)');

console.log('\n== BUOC 5: TLV structural walk tren tail (thu parser don gian) ==');
for (const hdr of [2, 12]) {
  const body = F.slice(hdr);
  // DER-ish TLV: 1B tag, 1B len
  let i = 0, ok = 0;
  while (i + 2 <= body.length) { const l = body[i + 1]; if (i + 2 + l > body.length) break; i += 2 + l; ok++; }
  console.log(`  header=${hdr}B, TLV(1B tag+1B len): tieu thu ${i}/${body.length}B trong ${ok} TLV ${i === body.length ? '<= FIT HOAN TOAN!' : ''}`);
}

console.log('\n== BUOC 6: phan tich dai (band) tung byte-position qua 5 mau ==');
console.log('align 18B dau tien:');
for (const k of keys) console.log(`  ${k}: ${hex(B[k])}`);
console.log('\nper-position: {values} span  (random-uniform ky vong span~205; span<=32 = STRUCTURAL)');
for (let p = 2; p < 18; p++) {
  const vs = keys.map(k => B[k][p]);
  const span = Math.max(...vs) - Math.min(...vs);
  const struct = span <= 32 ? '  <= STRUCTURAL' : (span <= 64 ? '  ?' : '');
  console.log(`  byte[${p}]: {${vs.map(v => v.toString(16).padStart(2, '0')).join(',')}} span=${span}${struct}`);
}

console.log('\n== BUOC 7: u64 BAND search trong S1 (day du 98B) ==');
const bands = [
  ['device-id band 7.60e18-7.70e18', 76n * 1000000000000000000n / 10n * 10n, 77n * 1000000000000000000n / 10n * 10n],
];
const LO64 = 7600000000000000000n, HI64 = 7700000000000000000n;
let bandHits = [];
for (let i = 0; i + 8 <= F.length; i++) for (const le of [false, true]) {
  const v = le ? F.readBigUInt64LE(i) : F.readBigUInt64BE(i);
  if (v >= LO64 && v <= HI64) bandHits.push(`  offset ${i} u64${le ? 'LE' : 'BE'} = ${v} <== TRONG DEVICE-ID BAND`);
  if (v >= 1786704000000n && v <= 1789060800000n) bandHits.push(`  offset ${i} u64${le ? 'LE' : 'BE'} = ${v} (ms-timestamp band)`);
}
console.log(bandHits.length ? bandHits.join('\n') : '  (khong co u64 window nao nam trong device-id/ms-timestamp band)');

console.log('\n== BUOC 8: hypothesis encoded-id — XOR/SUB alignment vs device_id ==');
// S1: device 7678616678053643790. S2/S3: device 7664923887225882119 (try 7674923... nuance).
const cand = [
  ['S1', BigInt(SEC.device_id)],
  ['S2/S3', 7664923887225882119n], ['S2/S3b', 7674923887225882119n],
];
for (const [sn, id] of cand) {
  const b = sn === 'S1' ? B.S1 : B.S2;
  for (let off = 2; off + 8 <= b.length; off++) {
    for (const le of [false, true]) {
      const v = le ? b.readBigUInt64LE(off) : b.readBigUInt64BE(off);
      const x = v ^ id, s = v > id ? v - id : id - v;
      if (x < 0x10000n) console.log(`  ${sn} bytes[${off}:${off + 8}] u64${le ? 'LE' : 'BE'} XOR ${id} = ${x.toString(16)} (XOR nho!)`);
      if (s < 0x100000n) console.log(`  ${sn} bytes[${off}:${off + 8}] u64${le ? 'LE' : 'BE'} SUB ${id} = ${s} (delta nho!)`);
    }
  }
}
console.log('  (neu khong co dong nao in ra: khong tim thay XOR/SUB alignment)');

console.log('\n== TOM LUAT DU LIEU ==');
console.log('byte2 cac mau:', keys.map(k => `${k}=${B[k][2].toString(16).padStart(2, '0')}`).join(' '));
