// t_ts_origin.mjs — CHỐT: ts_sign sinh ra từ đâu? (server-cấp vs device-ký)
//   Forge device no-phone → dsign → warmup. Xem d.ts_sign có được SERVER trả về không
//   (device.mjs lấy từ dsign resp; login.mjs:68 lấy từ response header tt-ticket-guard-server-data).
//   Nếu offline-forge nhận được ts.1.<...> từ RESPONSE ⇒ server-cấp ⇒ KHÔNG cần phone để có ts_sign.
//   Chạy: PROXY=.. RE_VER=45.0.3 NO_COMPILE=1 node re/tests/t_ts_origin.mjs
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { registerDevice, newIdentity, dsign } from '../src/device.mjs';
import { storeRegion, getNonce, appRegion, seedCookies } from '../src/login.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));
const show = (v) => v ? (String(v).slice(0, 46) + '…') : '(RỖNG)';

const id = newIdentity();
const r = await registerDevice(id);
if (!r.device_id) { console.log('❌ device_register fail:', JSON.stringify(r).slice(0, 150)); process.exit(1); }
const dev = { device_id: r.device_id, install_id: r.install_id, id };
console.log('[0] forge device_id=%s new_user=%s', r.device_id, r.new_user);

const d = await dsign(dev).catch((e) => ({ _err: e }));
if (!d.device_token) { console.log('❌ dsign fail:', d._err?.message); process.exit(1); }
seedCookies(d.cookies || {});
console.log('[1] SAU dsign:');
console.log('    dtoken_sign =', show(d.dtoken_sign), '  (server ký device_token)');
console.log('    ts_sign     =', show(d.ts_sign), '  ← ticket-guard token');

await storeRegion(dev, d).catch(() => {});
console.log('[2] SAU store_region:  ts_sign =', show(d.ts_sign));
await getNonce(dev, d).catch(() => {});
await appRegion(dev, d).catch(() => {});
console.log('[3] SAU warmup:        ts_sign =', show(d.ts_sign));

console.log('\n=== KẾT LUẬN ===');
if (d.ts_sign && /^ts\./.test(d.ts_sign)) console.log('🎉 ts_sign do SERVER trả về response (offline-forge vẫn nhận được) ⇒ KHÔNG phải device tự ký ⇒ offline-able.');
else console.log('⚠️ ts_sign vẫn RỖNG sau warmup — server chưa cấp ở các bước này (thử endpoint login/write-op, hoặc cần session).');
