// re/tests/diff_login.mjs — DIFF byte request user/login ta dựng vs genuine (→2135).
//   Mục tiêu: tìm ĐÚNG field khác biệt gây ec7. Chạy: JAVA_HOME=.. NO_COMPILE=1 PROXY_URL=.. node re/tests/diff_login.mjs
import '../src/net.mjs';
import fs from 'node:fs';
import { registerDevice, dsign } from '../src/device.mjs';
import { buildCall, enc } from '../src/login.mjs';

const qmap = (u) => Object.fromEntries(new URLSearchParams(u.split('?')[1] || ''));
const bmap = (b) => Object.fromEntries(new URLSearchParams(b || ''));

// genuine 45.0.3 (phone vừa gửi, cùng version signer → diff hoàn hảo)
const G = JSON.parse(fs.readFileSync(new URL('../ground-truth/03_login_450_genuine.json', import.meta.url), 'utf8'))[0];
const gq = qmap(G.url), gh = Object.fromEntries(Object.entries(G.req_headers || {}).map(([k, v]) => [k.toLowerCase(), v])), gb = bmap(G.req_body);

// mine
const dev = await registerDevice(); const d = await dsign(dev);
const M = buildCall(dev, d, '/passport/user/login/', { params: { password: enc('x'), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc('user2566145822112') } });
const mq = qmap(M.url), mh = Object.fromEntries(Object.entries(M.headers).map(([k, v]) => [k.toLowerCase(), String(v)])), mb = bmap(M.body);

const diffKeys = (a, b, label) => {
  const ak = new Set(Object.keys(a)), bk = new Set(Object.keys(b));
  const onlyG = [...ak].filter((k) => !bk.has(k)), onlyM = [...bk].filter((k) => !ak.has(k));
  console.log(`\n=== ${label} ===`);
  if (onlyG.length) console.log('  CHỈ genuine có (ta THIẾU):', onlyG.join(', '));
  if (onlyM.length) console.log('  CHỈ ta có (genuine KHÔNG):', onlyM.join(', '));
  if (!onlyG.length && !onlyM.length) console.log('  (cùng bộ key)');
};
diffKeys(gq, mq, 'QUERY params');
diffKeys(gh, mh, 'HEADERS');
diffKeys(gb, mb, 'BODY params');

// value diff query
console.log('\n=== QUERY value diff (field chung) ===');
for (const k of Object.keys(gq)) if (mq[k] !== undefined && gq[k] !== mq[k] && !['_rticket', 'ts', 'device_id', 'iid'].includes(k)) console.log(`  ${k}: genuine="${gq[k]}" | ta="${mq[k]}"`);
// value diff HEADER (mọi header chung; bỏ field time-bound/sig)
console.log('\n=== HEADER value diff (field chung, bỏ sig/time) ===');
const SKIP = new Set(['x-argus', 'x-gorgon', 'x-ladon', 'x-khronos', 'x-ss-req-ticket', 'x-ss-stub', 'x-tt-trace-id', 'content-length', 'tt-device-guard-client-data', 'tt-ticket-guard-public-key', 'cookie']);
for (const k of Object.keys(gh)) if (mh[k] !== undefined && !SKIP.has(k) && gh[k] !== mh[k]) console.log(`  ${k}: genuine="${String(gh[k]).slice(0, 50)}" | ta="${String(mh[k]).slice(0, 50)}"`);
// cookie content diff
console.log('\n=== COOKIE diff ===');
const gck = Object.fromEntries((gh['cookie'] || '').split(/;\s*|,\s*/).map((s) => s.split('=')).filter((a) => a[0]).map((a) => [a[0].trim(), a.slice(1).join('=')]));
const mck = Object.fromEntries((mh['cookie'] || '').split(/;\s*/).map((s) => s.split('=')).filter((a) => a[0]).map((a) => [a[0].trim(), a.slice(1).join('=')]));
console.log('  genuine cookie keys:', Object.keys(gck).join(', '));
console.log('  ta cookie keys    :', Object.keys(mck).join(', '));
console.log('\n=== BODY value diff ===');
for (const k of Object.keys(gb)) if (mb[k] !== undefined && k !== 'password' && k !== 'username' && gb[k] !== mb[k]) console.log(`  ${k}: genuine="${gb[k]}" | ta="${mb[k]}"`);
process.exit(0);
