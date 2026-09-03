// re/tests/t2_device.mjs — verify Task 2 (register) + Task 3 (dsign/guards).
//   Chạy: JAVA_HOME=... NO_COMPILE=1 PROXY_URL=... node re/tests/t2_device.mjs
import '../src/net.mjs';
import { registerDevice, dsign, guards } from '../src/device.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅', m); } else { fail++; console.log('  ❌', m); } };

console.log('[t2] registerDevice → server cấp device_id/install_id');
const dev = await registerDevice();
ok(/^\d{15,}$/.test(dev.device_id || ''), 'device_id hợp lệ: ' + dev.device_id);
ok(/^\d{15,}$/.test(dev.install_id || ''), 'install_id hợp lệ: ' + dev.install_id);
ok(dev.new_user === 1, 'new_user=1 (device MỚI): ' + dev.new_user);

console.log('[t3] dsign → device_token + "s"');
const d = await dsign(dev);
ok(/^1\|/.test(d.device_token || ''), 'device_token dạng 1|{...}: ' + (d.device_token || '').slice(0, 30));
ok(!!d.dtoken_sign, 'dtoken_sign có');
console.log('     ⇒ device_token "s" =', d.s, '(so genuine s=1; forge thường s=1 hoặc 0.6 — ghi STATUS)');

console.log('[t3] guards → device-guard + ticket-guard headers');
const g = guards(d, '/passport/user/login/', Math.floor(Date.now() / 1000), '');
ok(!!g['tt-device-guard-client-data'], 'có tt-device-guard-client-data');
ok(g['tt-ticket-guard-public-key'] === d.ecPub.toString('base64'), 'tt-ticket-guard-public-key khớp ecPub');
ok(g['tt-ticket-guard-version'] === '3', 'tt-ticket-guard-version=3 (khớp genuine)');
// decode lại device-guard blob → khớp cấu trúc genuine
const dgj = JSON.parse(Buffer.from(g['tt-device-guard-client-data'], 'base64').toString('utf8'));
ok(dgj.req_content === 'device_token,path,timestamp' && !!dgj.dreq_sign, 'device-guard blob khớp cấu trúc genuine (req_content+dreq_sign)');

console.log('\n[t2/t3] KẾT QUẢ:', pass, 'pass /', fail, 'fail  | device_id=' + dev.device_id + ' s=' + d.s);
process.exit(fail ? 1 : 0);
