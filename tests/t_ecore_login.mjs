// E-core LOGIN-gate qua proxy sạch: ec7 ở user/login = UNTRUSTED (chắc chắn, không mơ hồ như check_email 1105).
//  register device MỚI theo từng device-state config -> login account ngoại -> đọc ec.
//  pre_check in kèm để xác nhận account còn sống (tránh nhầm account-dead với trusted).
import '../src/net.mjs';
import { registerDevice, newIdentity, dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies } from '../src/login.mjs';

const USER = 'user5602420442843', PASS = '@33dp5YMAiCd';
const MSSTATE = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk/msstate_attk';
const V473 = { MSB_VER: '45.7.3', MSB_VERCODE: '2024507030' };
const configs = {
  C0_forge_baseline:   {},
  C1_keva_selfstore:   { MSB_FULLINIT: '1', MSB_KV: '1' },
  C3_feed_extract7665: { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE, ...V473 },
};
const verdict = (ec) => ec === 7 ? '❌UNTRUSTED(ec7)' : ec === 2135 ? '✅TRUSTED(2135 foreign-bind)' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅TRUSTED(success)' : 'other:' + ec;

for (const [name, env] of Object.entries(configs)) {
  try {
    const id = newIdentity();
    const reg = await registerDevice(id, env);
    if (!reg.device_id) { console.log(`\n=== ${name} === register FAIL`); continue; }
    const dev = { device_id: reg.device_id, install_id: reg.install_id, id };
    const d = await dsign(dev).catch((e) => ({ _err: e }));
    if (!d.device_token) { console.log(`\n=== ${name} did=${reg.device_id} === dsign FAIL ${d._err?.message}`); continue; }
    seedCookies(reg.cookies || {}); seedCookies(d.cookies || {});
    await warmup(dev, d).catch(() => {});
    const pc = await preCheck(USER, dev, d);
    const r = await userLogin(USER, PASS, dev, d);
    console.log(`\n=== ${name}  did=${reg.device_id} new_user=${reg.new_user} ===`);
    console.log(`  pre_check ec=${pc.ec}  raw=${JSON.stringify(pc.j?.data || pc.txt || '').slice(0, 140)}`);
    console.log(`  user/login ec=${r.ec}  => ${verdict(r.ec)}`);
  } catch (e) { console.log(`\n=== ${name} === ERR ${e.message}`); }
}
console.log('\n=== DOC: login ec7 = untrusted (tu sinh khong cuu). 2135/success = TRUSTED (breakthrough). pre_check xac nhan account song. ===');
