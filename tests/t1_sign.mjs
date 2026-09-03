// re/tests/t1_sign.mjs — verify Task 1 signing layer.
//   Chạy: JAVA_HOME=... NO_COMPILE=1 node re/tests/t1_sign.mjs
import { metasecBlock, signMetasec, genuineHeaders, CLIENT_GENUINE } from '../src/sign.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅', m); } else { fail++; console.log('  ❌', m); } };

console.log('[t1] metasec signer format');
const ts = Math.floor(Date.now() / 1000);
const block = metasecBlock({ stub: '01205F31B47EC9C72AB1A5555960AA63', reqTicket: Date.now(), cookie: 'store-idc=alisg' });
const sig = signMetasec('https://api16-normal-c-alisg.tiktokv.com/passport/user/login/?aid=1233', block, ts);
ok(/^8404/.test(sig['X-Gorgon'] || ''), 'x-gorgon prefix 8404 (khớp genuine 840400cd…): ' + (sig['X-Gorgon'] || '').slice(0, 12));
ok(String(sig['X-Khronos']) === String(ts), 'x-khronos = ts giây: ' + sig['X-Khronos']);
ok((sig['X-Argus'] || '').length > 40, 'x-argus có (len ' + (sig['X-Argus'] || '').length + ')');
ok((sig['X-Ladon'] || '').length > 20, 'x-ladon có (len ' + (sig['X-Ladon'] || '').length + ')');

console.log('[t1] genuineHeaders có ĐỦ header client-genuine (trước thiếu → nghi ec7)');
const h = genuineHeaders({ body: 'a=1', reqTicketMs: Date.now(), cookie: 'store-idc=alisg' });
for (const k of ['oec-cs-sdk-version', 'oec-cs-si-a', 'oec-vc-sdk-version', 'rpc-persist-pns-region-1', 'rpc-persist-pns-region-2', 'rpc-persist-pns-region-3', 'x-tt-pba-encode', 'x-tt-request-tag'])
  ok(h[k] === CLIENT_GENUINE[k], 'có ' + k + ' = ' + h[k]);
ok(h['x-tt-request-tag'] === 'n=0;nr=011;bg=0;s=-1;p=0', 'x-tt-request-tag ĐẦY ĐỦ (không phải s=-1;p=0)');
ok(/^[0-9A-F]{32}$/.test(h['x-ss-stub'] || ''), 'x-ss-stub = MD5(body) 32-hex UPPERCASE: ' + h['x-ss-stub']);

console.log('\n[t1] KẾT QUẢ:', pass, 'pass /', fail, 'fail');
process.exit(fail ? 1 : 0);
