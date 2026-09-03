// t_trust_new.mjs — đo trust 1 device qua env (DID/IID/OUD/GAID/CDID), offline sign, route qua PROXY_URL sạch.
//  check_email = trust-gate (không cần cdid). login = gate mạnh hơn.
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies, passportCall, enc } from '../src/login.mjs';
const dev = {
  device_id: process.env.DID, install_id: process.env.IID,
  id: { openudid: process.env.OUD, cdid: process.env.CDID || '00000000-0000-0000-0000-000000000000',
        clientudid: process.env.CUD || '00000000-0000-0000-0000-000000000001', google_aid: process.env.GAID },
};
const USER = process.env.RU || 'user28122299571120', PASS = process.env.RP || '@K4a@RWnq0RMO';
const v = (ec) => ec === 7 ? '❌UNTRUSTED(ec7)' : ec === 1105 ? '⚠️1105(risk/captcha)' : ec === 2135 ? '✅TRUSTED(2135)' : (ec === 0 || ec === 1091 || ec === 'success' || ec === 1011) ? '✅TRUSTED(' + ec + ')' : 'other:' + ec;
const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign s=%s token=%s %s', d.s, !!d.device_token, d._err?.message || '');
if (!d.device_token) { console.log('dsign FAIL -> cannot measure'); process.exit(1); }
seedCookies(d.cookies || {}); await warmup(dev, d).catch(() => {});
const pc = await preCheck(USER, dev, d); console.log('pre_check ec=%s %s', pc.ec, JSON.stringify(pc.j?.data || '').slice(0, 90));
const ce = await passportCall(dev, d, '/passport/user/check_email_registered', { params: { account_sdk_source: 'app', multi_login: '1', email: enc('chk' + Date.now() + '@gmail.com'), mix_mode: '1' } });
console.log('check_email ec=%s msg=%s  => %s', ce.ec, ce.j?.message, v(ce.ec));
const r = await userLogin(USER, PASS, dev, d); console.log('user/login ec=%s desc="%s"  => %s', r.ec, (r.j?.data?.description || '').slice(0, 50), v(r.ec));
