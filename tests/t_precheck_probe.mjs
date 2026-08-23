// t_precheck_probe.mjs — cô lập: user/login CÓ warmup+pre_check trước (chuỗi genuine #9→#12) có tránh ec7 không?
//   1 forge device → warmup(storeRegion/getNonce/appRegion) → pre_check → user/login. In ec từng bước.
//   So với login_2135.mjs PW_LOGIN (nhảy thẳng user/login, KHÔNG pre_check) → ec7.
//   Chạy: PROXY=... node re/tests/t_precheck_probe.mjs "user|pass"
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { registerDevice, dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, storeRegion, getNonce, appRegion } from '../src/login.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));
const [user, pass] = (process.argv[2] || '').split('|');
if (!user || !pass) { console.error('cần "user|pass"'); process.exit(1); }

const ecOf = (r) => r?.ec ?? r?.j?.data?.error_code ?? r?.j?.message ?? r?._err?.message ?? '(?)';
(async () => {
  const dev = await registerDevice();
  const d = await dsign(dev);
  console.log('device', dev.device_id, 'dsign_s=', d.s, 'new_user=', dev.new_user);

  // warmup FULL (genuine trước user/login): store_region → get_nonce → app/region → pre_check
  const sr = await storeRegion(dev, d).catch((e) => ({ _err: e }));
  const gn = await getNonce(dev, d).catch((e) => ({ _err: e }));
  const ar = await appRegion(dev, d).catch((e) => ({ _err: e }));
  console.log('warmup: store_region=', ecOf(sr), '| get_nonce=', ecOf(gn), '| app_region=', ecOf(ar));
  const pc = await preCheck(user, dev, d).catch((e) => ({ _err: e }));
  console.log('pre_check=', ecOf(pc), '|', JSON.stringify(pc?.j?.data || pc?.j || '').slice(0, 120));

  // user/login (SAU khi đã warmup+pre_check)
  const lg = await userLogin(user, pass, dev, d).catch((e) => ({ _err: e }));
  const ec = ecOf(lg);
  console.log('user/login=', ec, '|', JSON.stringify(lg?.j?.data || lg?.j || '').slice(0, 160));
  console.log(String(ec) === '2135' ? '✅ 2135 — pre_check GIÚP (user/login qua khi có warmup)' : ec === 7 ? '❌ ec7 — pre_check KHÔNG cứu (provider/device gate user/login)' : 'ec khác=' + ec);
})();
