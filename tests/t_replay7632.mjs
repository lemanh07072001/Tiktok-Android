// Extract-then-replay 7632 (TRUSTED) NO-PHONE: identity THẬT bắt từ mitm (mod dedup 7632) + device_id 7632 + install_id từ resp.
//  Ký OFFLINE (signer default) + route qua PROXY_URL sạch. user/login ec7 = untrusted; 2135/0 = TRUSTED => replay proven.
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies, passportCall, enc } from '../src/login.mjs';

const dev = {
  device_id: '7632162877655729682', install_id: '7664810491785971476',
  id: { openudid: 'b646b530c454cd5b', cdid: 'a98a6dde-af73-43de-8a1b-480e41ca03cc',
        clientudid: '42cc984f-525e-4ea8-8e29-044c0d6f7a40', google_aid: '97f093b7-b489-41c5-8b9a-7e028cbfe49a' },
};
const USER = process.env.RU || 'user28122299571120', PASS = process.env.RP || '@K4a@RWnq0RMO';  // account quen device 7632, chua bi velocity hom nay
const v = (ec) => ec === 7 ? '❌UNTRUSTED(ec7)' : ec === 2135 ? '✅TRUSTED(2135)' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅TRUSTED(success)' : 'other:' + ec;

const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign s=%s token=%s %s', d.s, !!d.device_token, d._err?.message || '');
if (!d.device_token) { console.log('dsign FAIL -> abort'); process.exit(1); }
seedCookies(d.cookies || {});
await warmup(dev, d).catch(() => {});
const pc = await preCheck(USER, dev, d);
console.log('pre_check ec=%s data=%s', pc.ec, JSON.stringify(pc.j?.data || '').slice(0, 120));
const r = await userLogin(USER, PASS, dev, d);
console.log('user/login ec=%s data=%s', r.ec, JSON.stringify(r.j?.data || '').slice(0, 180));
console.log('=> %s', v(r.ec));
const ce = await passportCall(dev, d, '/passport/user/check_email_registered', { params: { account_sdk_source: 'app', multi_login: '1', email: enc('chkreplay' + Date.now() + '@gmail.com'), mix_mode: '1' } });
console.log('check_email ec=%s (1105=untrusted/risk-captcha, 1011/success=trusted gate)', ce.ec);
