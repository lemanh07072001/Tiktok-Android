// _f24_mask.js — BUOC 9: kiem dinh chac che cau truc header 10B + giai mask
'use strict';
const hex = b => Buffer.from(b).toString('hex');
const S1 = Buffer.from('MDGkEprSrHADIDZ6yWtkztTtnLIoFXUlUzcso/xeHUnQLB3XQDc6HAV+FRzlNQOm2ekPLgHBxRSevg7OUKLwWVSQx2CKVuYBe4tnmkAW7TRq/cERFu7jpn8VOSyBvYKYAfE=', 'base64');
const S2 = Buffer.from('MDGnGpXSpHsBJj8xg2wyzoO2', 'base64'); // device 7664923 (phone genuine)
const S3 = Buffer.from('MDGnGpXSpHsBJj8x0TFixYfj', 'base64'); // device 7664923 (store-driven)
const S4 = Buffer.from('MDGlHJrUpXIAIT18yWxjztXj', 'base64'); // _ds7666
const S5 = Buffer.from('MDGkHJnbrHMFJzt4yTwzldTh', 'base64'); // stub-built (note 32)
const ALL = { S1, S2, S3, S4, S5 };

console.log('== 9a. high-nibble constancy, bytes 2..11 (5 mau, 4 device-doc) ==');
for (let p = 2; p <= 11; p++) {
  const his = Object.entries(ALL).map(([k, b]) => [k, b[p] >> 4]);
  const set = [...new Set(his.map(x => x[1]))];
  console.log(`  byte[${p}]: {${his.map(x => x[0] + ':' + x[1].toString(16)).join(',')}} distinct=${set.length}${set.length === 1 ? '  CONST' : ''}`);
}
console.log('== 9b. pairwise XOR bytes 2..11 (ky vong: <=0x0f neu la digit/BCD mask) ==');
const pairs = [['S1', 'S2'], ['S1', 'S3'], ['S1', 'S4'], ['S1', 'S5'], ['S4', 'S5'], ['S2', 'S3']];
for (const [a, b] of pairs) {
  const x = Buffer.from(S1 && ALL[a].slice(2, 12).map((v, i) => v ^ ALL[b][i + 2]));
  const maxB = Math.max(...x);
  console.log(`  ${a}^${b}: ${hex(x)}  max=0x${maxB.toString(16)}${maxB <= 0x0f ? '  <= TOAN NHO (digit-region)' : ''}`);
}

console.log('\n== 9c. brute-force giai mask: hypothesis BCD/XOR + device_id ==');
// Vung pt = 20 nibbles. Ung vien digit-stream tu device cua tung mau.
const cands1 = { // cho S1 (device 7678616678053643790)
  'devid19': '7678616678053643790',
  '0+devid': '07678616678053643790',
  'devid+0': '76786166780536437900',
  'devid_rev': '09734635087661876867',
  'iid19': '7679520991450973970',
  '0+iid': '07679520991450973970',
};
const cands23 = {
  'devid19': '7664923887225882119',
  '0+devid': '07664923887225882119',
  'devid+0': '76649238872258821190',
  'devid19b': '7674923887225882119',
  '0+devidb': '07674923887225882119',
};
const nib = (buf, i) => (i % 2 === 0 ? buf[i >> 1] >> 4 : buf[i >> 1] & 0xf);
let solved = [];
for (const [cn, ds] of Object.entries(cands1)) {
  if (ds.length !== 20) continue;
  const digits = ds.split('').map(Number);
  // mask nibble i = ctNib(i) XOR digitNib(i); digitNib = digits[i] (BCD)
  const mask = []; let okAll = true;
  for (let i = 0; i < 20; i++) {
    const m = nib(S1, i) ^ digits[i];
    mask.push(m);
  }
  // verify S2/S3 voi moi ung vien DID cua chung
  for (const [cn23, ds23] of Object.entries(cands23)) {
    const d23 = ds23.split('').map(Number);
    let hit = 0;
    for (const S of [S2, S3]) { let ok = true; for (let i = 0; i < 20; i++) if ((nib(S, i) ^ mask[i]) !== d23[i]) { ok = false; break; } if (ok) hit++; }
    if (hit) solved.push(`  BCD-XOR: S1="${cn}" + S2/S3="${cn23}" -> ${hit}/2 mau verify! mask=${mask.map(m => m.toString(16)).join('')}`);
  }
}
// thu add mod 16
for (const [cn, ds] of Object.entries(cands1)) {
  if (ds.length !== 20) continue;
  const digits = ds.split('').map(Number);
  const mask = []; for (let i = 0; i < 20; i++) mask.push((nib(S1, i) - digits[i] + 16) & 0xf);
  for (const [cn23, ds23] of Object.entries(cands23)) {
    const d23 = ds23.split('').map(Number);
    let hit = 0;
    for (const S of [S2, S3]) { let ok = true; for (let i = 0; i < 20; i++) if (((nib(S, i) - mask[i] + 16) & 0xf) !== d23[i]) { ok = false; break; } if (ok) hit++; }
    if (hit) solved.push(`  BCD-ADD: S1="${cn}" + S2/S3="${cn23}" -> ${hit}/2 mau verify! mask=${mask.map(m => m.toString(16)).join('')}`);
  }
}
// thu encode ASCII 2-digit/byte: byte pt = 'dd' (0x30+d1, 0x30+d2) — vung 10B=10 digit chars thoi (it hon 19) -> thu align offset trong digit-string
for (const off of [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]) {
  const ds = cands1['devid19'];
  const sub = ds.slice(off, off + 10); if (sub.length < 10) continue;
  const mask = []; for (let i = 0; i < 10; i++) mask.push(S1[i + 2] ^ (0x30 + Number(sub[i])));
  for (const [cn23, ds23] of Object.entries({ 'devid19': cands23['devid19'], 'devid19b': cands23['devid19b'] })) {
    const sub23 = ds23.slice(off, off + 10);
    let hit = 0;
    for (const S of [S2, S3]) { let ok = true; for (let i = 0; i < 10; i++) if ((S[i + 2] ^ mask[i]) !== (0x30 + Number(sub23[i]))) { ok = false; break; } if (ok) hit++; }
    if (hit) solved.push(`  ASCII-digit: S1 devid[${off}:${off + 10}] + S2/S3 "${cn23}" -> ${hit}/2! mask=${mask.map(m => m.toString(16).padStart(2, '0')).join('')}`);
  }
}
console.log(solved.length ? solved.join('\n') : '  (khong cop ra hypothesis nao: vung 10B KHONG phai device_id o cac encoding thu)');

console.log('\n== 9d. low-nibble span chi tiet (digits co phai 0-9?) ==');
for (let p = 2; p <= 11; p++) {
  const los = Object.values(ALL).map(b => b[p] & 0xf);
  const span = Math.max(...los) - Math.min(...los);
  console.log(`  byte[${p}] low-nibbles {${los.map(v => v.toString(16)).join(',')}} span=${span}${span <= 9 ? '  (vua du digit 0-9)' : span <= 15 ? '  (hex-nibble)' : ''}`);
}
