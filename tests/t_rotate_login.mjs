// XOAY device_id MỚI + LOGIN API: register offline với openudid ĐÃ ROTATE trên phone (b7e9ba7a...) qua proxy sạch.
//  openudid mới = SSAID rotate thật (không forge random) → server cấp device_id mới. Đo trust bằng login-gate.
import '../src/net.mjs';
import { registerDevice, dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';

// identity ĐÃ ROTATE trên phone (verify: SSAID=b7e9ba7ab25a0ec5, GSF=7631496797811468732, serial=bc5b84e8b622765f)
const id = {
  openudid: '5b41298a86a7be93',
  cdid: crypto.randomUUID(),               // cdid client-gen (app tự sinh, không server-bound lúc register)
  clientudid: crypto.randomUUID(),
  google_aid: 'd7e79a76-65fc-4e5b-9fe6-bceb594e343f',  // GAID rotate
  req_id: crypto.randomUUID(),
};
const USER = process.env.RU || 'user28122299571120', PASS = process.env.RP || '@K4a@RWnq0RMO';
const v = (ec) => ec === 7 ? '❌ec7(untrusted)' : ec === 2135 ? '✅2135(trusted)' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅success(trusted)' : 'other:' + ec;

const reg = await registerDevice(id);
console.log('register → device_id=%s install_id=%s new_user=%s', reg.device_id, reg.install_id, reg.new_user);
if (!reg.device_id) { console.log('register FAIL', JSON.stringify(reg.raw||{}).slice(0,150)); process.exit(1); }
const dev = { device_id: reg.device_id, install_id: reg.install_id, id };
const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign s=%s token=%s %s', d.s, !!d.device_token, d._err?.message || '');
if (!d.device_token) process.exit(1);
seedCookies(reg.cookies || {}); seedCookies(d.cookies || {});
await warmup(dev, d).catch(() => {});
const pc = await preCheck(USER, dev, d);
console.log('pre_check ec=%s', pc.ec);
const r = await userLogin(USER, PASS, dev, d);
console.log('user/login ec=%s data=%s', r.ec, JSON.stringify(r.j?.data||'').slice(0,140));
console.log('=> DEVICE %s : %s', reg.device_id, v(r.ec));
