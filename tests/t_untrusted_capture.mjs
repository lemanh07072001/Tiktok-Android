// t_untrusted_capture.mjs — GAP #1: bat mau UNTRUSTED sach (forge device FULLY OFFLINE, khong phone).
//   Forge fresh identity -> device_register (unidbg x-argus) -> capture request -> diff vs trusted 7632.
//   Deliverable chinh = REQUEST (body+x-argus) de diff (doc lap IP). Login-ec7 optional (arg combo), co the confound IP.
import '../src/net.mjs';
import { registerDevice, newIdentity } from '../src/device.mjs';
import fs from 'node:fs';

// monkeypatch fetch -> capture device_register request
const orig = globalThis.fetch;
let cap = null;
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  const r = await orig(url, opts);
  if (u.includes('device_register')) cap = { url: u, headers: opts.headers, body: opts.body };
  return r;
};

console.log('[gap1] forge fresh device (fully offline, unidbg x-argus)...');
const id = newIdentity();
let dev;
try {
  dev = await registerDevice(id);
} catch (e) {
  console.log('  !! registerDevice loi:', e.message, '(signer unidbg can JDK21+maven)'); process.exit(1);
}
console.log('  device_id=%s install_id=%s new_user=%s', dev.device_id, dev.install_id, dev.new_user);
if (!cap) { console.log('  !! khong capture duoc request'); process.exit(1); }

const xa = cap.headers['x-argus'] || cap.headers['X-Argus'] || '';
const xl = cap.headers['x-ladon'] || cap.headers['X-Ladon'] || '';
const xg = cap.headers['x-gorgon'] || cap.headers['X-Gorgon'] || '';
console.log('  x-argus len=%d (genuine device_register=344) | x-ladon len=%d | x-gorgon len=%d', xa.length, xl.length, xg.length);

const out = 'ground-truth/untrusted_devreg.json';
fs.writeFileSync(out, JSON.stringify({ url: cap.url, headers: cap.headers, body: cap.body, device_id: dev.device_id, new_user: dev.new_user, id, resp: dev.raw }, null, 2));
console.log('  saved ->', 're/' + out);

// ===== DIFF header vs trusted 7632 (raw_devreg_req.bin) =====
const trusted = JSON.parse(fs.readFileSync('ground-truth/raw_devreg_req.bin', 'utf8'));
const mine = JSON.parse(cap.body);
const flat = (o, p = '') => { const r = {}; for (const k in o) { const v = o[k]; if (v && typeof v === 'object') Object.assign(r, flat(v, p + k + '.')); else r[p + k] = v; } return r; };
const ft = flat(trusted.header), fm = flat(mine.header);
const kt = new Set(Object.keys(ft)), km = new Set(Object.keys(fm));

console.log('\n=== DIFF device_register.header: TRUSTED(7632, genuine) vs UNTRUSTED(forge offline) ===');
console.log('  [chi TRUSTED co]:', [...kt].filter(k => !km.has(k)).join(', ') || '(none)');
console.log('  [chi FORGE co]  :', [...km].filter(k => !kt.has(k)).join(', ') || '(none)');
console.log('  [gia tri khac o field chung] (bo qua version/id/fingerprint-random):');
const IGNORE = /version|_code|device_id|install_id|openudid|clientudid|cdid|google_aid|req_id|release_build|git_hash|rom|build|resolution|model|brand|manufacturer|dpi|density|_gen|install_time/i;
for (const k of [...kt].filter(k => km.has(k))) {
  if (String(ft[k]) !== String(fm[k])) {
    const flag = IGNORE.test(k) ? '' : '   <== NGHI trust-signal';
    console.log(`    ${k}: trusted=${JSON.stringify(ft[k])} forge=${JSON.stringify(fm[k])}${flag}`);
  }
}
console.log('\n  top-level keys: trusted=%s | forge=%s', Object.keys(trusted).join(','), Object.keys(mine).join(','));
