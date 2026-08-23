// Đo trust device MỚI vừa register on-phone (7665549...) qua proxy sạch — phân giải "lớp giấu root hiện tại đủ chưa".
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
const dev = {
  device_id: process.env.DID || '7665549046120433172',
  install_id: process.env.IID || '7665552654689339157',
  id: { openudid: process.env.OUD || 'e09cf41303c1775b', cdid: process.env.CDID || '043dae1d-0d3e-4624-bf6a-4551502603ef',
        clientudid: '00000000-0000-4000-8000-000000000000', google_aid: '00000000-0000-4000-8000-000000000000' },
};
const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign token=%s %s', !!d.device_token, d._err?.message || '');
if (!d.device_token) process.exit(1);
seedCookies(d.cookies || {});
const r = await passportCall(dev, d, '/passport/user/check_email_registered', {
  params: { account_sdk_source: 'app', multi_login: '1', email: enc('newdev' + Date.now() + '@gmail.com'), mix_mode: '1' },
});
const ok = (r.ec === 'success' || r.ec === 1011 || r.ec === 0);
console.log('check_email %s ec=%s => %s', dev.device_id, r.ec, ok ? '✅TRUSTED(gate)' : '❌UNTRUSTED/risk');
