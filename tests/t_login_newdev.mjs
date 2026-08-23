// Login NO-PHONE trên device TRUSTED mới 7665549 (feed device-state khớp + identity mitm + session thật), ký offline, proxy sạch.
// 2135/success = TRUSTED (login-gate no-phone proven). ec7 = feed chưa đủ nhất quán.
import fs from 'node:fs';
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, preCheck, seedCookies, JAR } from '../src/login.mjs';
const line = fs.readFileSync('re/out/phone_accounts.txt', 'utf8').split(/\r?\n/).find((l) => l.startsWith('user28122299571120|'));
const f = line.split('|'); const TT = f[9], CK = f[10];
const dev = {
  device_id: '7665549046120433172', install_id: '7665552654689339157',
  id: { openudid: 'e09cf41303c1775b', cdid: '043dae1d-0d3e-4624-bf6a-4551502603ef',
        clientudid: '00000000-0000-4000-8000-000000000000', google_aid: '00000000-0000-4000-8000-000000000000' },
};
for (const kv of CK.split('; ')) { const i = kv.indexOf('='); if (i > 0) JAR[kv.slice(0, i).trim()] = kv.slice(i + 1); }
const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign token=%s %s', !!d.device_token, d._err?.message || '');
if (!d.device_token) process.exit(1);
seedCookies(d.cookies || {});
const pc = await preCheck('user28122299571120', dev, d); console.log('pre_check ec=%s', pc.ec);
const r = await userLogin('user28122299571120', '@K4a@RWnq0RMO', dev, d);
console.log('user/login ec=%s data=%s', r.ec, JSON.stringify(r.j?.data || '').slice(0, 160));
const ec = r.ec;
console.log('=> %s', ec === 7 ? '❌ec7' : ec === 2135 ? '✅TRUSTED(2135)' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅TRUSTED(success)' : 'other ' + ec);
