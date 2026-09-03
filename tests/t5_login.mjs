// re/tests/t5_login.mjs — PIVOTAL: user/login với FULL genuine headers → 2135 hay ec7?
//   Chạy: JAVA_HOME=.. NO_COMPILE=1 PROXY_URL=.. node re/tests/t5_login.mjs "<user>|<pass>"
import '../src/net.mjs';
import { registerDevice, dsign } from '../src/device.mjs';
import { preCheck, userLogin, seedCookies, warmup } from '../src/login.mjs';

const combo = (process.argv[2] || '').split('|');
const username = combo[0], password = combo[1];
if (!username || !password) { console.log('cần "<user>|<pass>"'); process.exit(2); }

console.log('[t5] register + dsign device mới');
const dev = await registerDevice();
const d = await dsign(dev);
seedCookies(dev.cookies); seedCookies(d.cookies);   // odin_tt device cookie → login jar
console.log('     device_id=' + dev.device_id + ' s=' + d.s + ' | cookies=' + Object.keys({ ...dev.cookies, ...d.cookies }).join(','));

console.log('[t5] warmup (store_region→get_nonce→app/region) lập odin_tt');
const ck = await warmup(dev, d);
console.log('     cookies sau warmup:', ck.join(','));

console.log('[t5] pre_check', username);
const pc = await preCheck(username, dev, d);
console.log('     ec=' + pc.ec + ' login_page=' + (pc.j?.data?.login_page || '?'));

console.log('[t5] user/login (PASSWORD, FULL genuine headers)');
const lg = await userLogin(username, password, dev, d);
console.log('     http=' + lg.status + ' ec=' + lg.ec);
console.log('     resp=' + (lg.txt || '').slice(0, 200));

const isEc7 = lg.ec === 7;
const is2135 = lg.ec === 2135;
console.log('\n=== KẾT LUẬN ===');
if (is2135) console.log('🎉🎉 2135 (KHÔNG ec7)! → header client-genuine LÀ gốc ec7 → logic trước SAI, RE đúng. aaas_ticket=' + (lg.j?.data?.aaas_ticket || '?'));
else if (isEc7) console.log('❌ vẫn ec7 → header genuine CHƯA đủ. Cần diff sâu hơn (body/query/cookie/order). KHÔNG kết luận bất khả.');
else console.log('⚠️ ec khác: ' + lg.ec + ' (không phải 2135 cũng không ec7) — phân tích resp.');
process.exit(is2135 ? 0 : 1);
