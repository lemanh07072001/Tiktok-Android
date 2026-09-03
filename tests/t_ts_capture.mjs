// t_ts_capture.mjs — bắt MẪU tt-ticket-guard-server-data (server trả gì) KHÔNG cần login.
//   Gửi endpoint passport kèm keepTgClientData:true (client GỬI tt-ticket-guard-client-data + pubkey)
//   → nếu server làm ticket-guard handshake, nó trả tt-ticket-guard-server-data (TS_DEBUG dump raw+decoded).
//   Chạy: TS_DEBUG=1 PROXY=.. RE_VER=45.0.3 NO_COMPILE=1 node re/tests/t_ts_capture.mjs
import crypto from 'node:crypto';
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { registerDevice, newIdentity, dsign } from '../src/device.mjs';
import { passportCall, seedCookies } from '../src/login.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));

const id = newIdentity();
const r = await registerDevice(id);
if (!r.device_id) { console.log('❌ device_register fail:', JSON.stringify(r).slice(0, 150)); process.exit(1); }
const dev = { device_id: r.device_id, install_id: r.install_id, id };
const d = await dsign(dev).catch((e) => ({ _err: e }));
if (!d.device_token) { console.log('❌ dsign fail:', d._err?.message); process.exit(1); }
seedCookies(d.cookies || {});
console.log('[0] forge=%s  dtoken_sign=%s  ts_sign(init)=%s', dev.device_id, d.dtoken_sign ? 'OK' : 'no', d.ts_sign || '(RỖNG)');

const eps = [
  ['/passport/app/store_region/', { params: { store_region_src: 'uid' } }],
  ['/passport/app/region/', { params: { type: '2', hashed_id: crypto.createHash('sha256').update(dev.device_id).digest('hex') } }],
  ['/passport/auth/get_nonce/', { params: { platform: 'google' } }],
  ['/passport/user/login/pre_check/', { params: { account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: '0f0a0b070e58585a5f' } }],
];
for (const [p, o] of eps) {
  const rr = await passportCall(dev, d, p, { ...o, keepTgClientData: true }).catch((e) => ({ ec: e.message }));
  console.log('[%s] ec=%s  ts_sign_now=%s', p, rr.ec, d.ts_sign ? d.ts_sign.slice(0, 34) + '…' : '(RỖNG)');
}
console.log('\n=== ts_sign cuối = %s ===', d.ts_sign || '(RỖNG — server chưa handshake ở các endpoint no-session này)');
