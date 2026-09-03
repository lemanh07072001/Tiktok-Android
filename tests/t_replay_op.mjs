// Authed NO-PHONE op trên device trusted 7632 bằng SESSION THẬT (user28122, còn hạn), ký offline, proxy sạch.
//  Không đụng user/login => không bị velocity-login che. So default vs feed device-state 7632 (env MSB_DEVSTATE_DIR).
//  Đọc session thẳng từ re/out/phone_accounts.txt (dòng user28122) => tránh chép nhầm.
import fs from 'node:fs';
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { passportCall, seedCookies, JAR } from '../src/login.mjs';

const line = fs.readFileSync('re/out/phone_accounts.txt', 'utf8').split(/\r?\n/)
  .find((l) => l.startsWith('user28122299571120|'));
if (!line) { console.log('KHONG tim thay dong user28122'); process.exit(1); }
const f = line.split('|');
const TT = f[9], CK = f[10];
const dev = {
  device_id: f[6], install_id: f[7],
  id: { openudid: 'b646b530c454cd5b', cdid: 'a98a6dde-af73-43de-8a1b-480e41ca03cc',
        clientudid: '42cc984f-525e-4ea8-8e29-044c0d6f7a40', google_aid: '97f093b7-b489-41c5-8b9a-7e028cbfe49a' },
};
console.log('dev=%s iid=%s TTlen=%d CKlen=%d', dev.device_id, dev.install_id, TT.length, CK.length);
for (const kv of CK.split('; ')) { const i = kv.indexOf('='); if (i > 0) JAR[kv.slice(0, i).trim()] = kv.slice(i + 1); }

const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign token=%s %s', !!d.device_token, d._err?.message || '');
if (!d.device_token) process.exit(1);
seedCookies(d.cookies || {});
const r = await passportCall(dev, d, '/passport/account/info/v2/', {
  params: { scene: 'normal', multi_login: '1', account_sdk_source: 'app', passport_sdk_version: '1' }, ttToken: TT,
});
const uid = r.j?.data?.user_id_str || r.j?.data?.user_id;
console.log('account/info status=%s ec=%s', r.status, r.ec);
console.log('  data=%s', JSON.stringify(r.j?.data || r.j || r.txt || '').slice(0, 320));
console.log('  => %s', uid ? ('✅ AUTHED NO-PHONE OP ok uid=' + uid) : ('❌ ' + (r.ec || r.status)));
