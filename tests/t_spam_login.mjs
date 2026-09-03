// Spam login user|pass (bỏ cookie), FEED device-state (x-argus genuine-grade) trên device trusted.
//   Mỗi account thử N lần. ec7 = rotate device_id KHÁC (dùng device-state đã extract khác) rồi login tiếp.
//   Env: MSB_DEVSTATE_DIR/MS_VENDOR... set sẵn (feed). Device pool = list DID|IID|DEVSTATE.
import '../src/net.mjs';
import fs from 'node:fs';
import { dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies } from '../src/login.mjs';

// Pool device trusted đã extract device-state. Mỗi entry: {did, iid, oud, gaid, state}
const POOL = [
  { did: '7665624514735244821', iid: '7665628081449109268', oud: 'c0c0ba3f5d16f614', gaid: 'b13dc71a-a0d0-4509-8450-dae659764fbb', state: 'msstate_7665624' },
  { did: '7665549046120433172', iid: '7665552654689339157', oud: '9fad4e30b02dbdda', gaid: '', state: 'msstate_7665549' },
];
const ATTK = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk';
const accounts = fs.readFileSync('re/tests/_spam_accounts.txt', 'utf8').trim().split('\n').map(l => l.split('|'));
const TRIES = Number(process.env.TRIES || 2);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const label = (ec) => ec === 7 ? '❌ec7' : ec === 2135 ? '✅2135' : ec === 1108 ? '✅1108' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅SUCCESS' : ec === 1105 ? '⚠️captcha' : 'ec' + ec;

// signer feed device-state set qua process.env TRƯỚC khi import sign — nhưng signOffline đọc process.env mỗi lần gọi,
// nên đổi DEVSTATE giữa chừng = set process.env.MSB_DEVSTATE_DIR trước mỗi login.
function useDevice(p) {
  process.env.MSB_DEVSTATE_DIR = `${ATTK}/${p.state}`;
  process.env.MS_VENDOR = 'libs_trill/'; process.env.MS_LIBS = 'libs_trill';
  process.env.MS_SIGN_OFF = '0x9ecc0'; process.env.MS_DISP_OFF = '0x11a1e0';
  process.env.MS_LICENSE_FILE = 'license_mus4573.json';
  process.env.MSB_VER = '45.7.3'; process.env.MSB_VERCODE = '2024507030';
  process.env.MSB_FULLINIT = '1'; process.env.MSB_KV = '1';
  process.env.APP_VER = '45.7.3'; process.env.APP_VC = '2024507030';
  return { device_id: p.did, install_id: p.iid, id: { openudid: p.oud, cdid: '00000000-0000-4000-8000-000000000001', clientudid: '00000000-0000-4000-8000-000000000002', google_aid: p.gaid || '00000000-0000-4000-8000-000000000000' } };
}

async function tryLogin(user, pass, p) {
  const dev = useDevice(p);
  const d = await dsign(dev).catch(e => ({ _err: e }));
  if (!d.device_token) return { ec: 'dsign-fail', err: d._err?.message };
  seedCookies(d.cookies || {});
  await warmup(dev, d).catch(() => {});
  await preCheck(user, dev, d).catch(() => {});
  const r = await userLogin(user, pass, dev, d);
  return { ec: r.j?.data?.error_code ?? r.j?.message, uid: r.j?.data?.user_id_str, desc: (r.j?.data?.description || '').slice(0, 50) };
}

for (const [user, pass] of accounts) {
  console.log(`\n═══ ${user} ═══`);
  let poolIdx = 0;
  for (let t = 1; t <= TRIES; t++) {
    let p = POOL[poolIdx % POOL.length];
    let r = await tryLogin(user, pass, p);
    console.log(`  #${t} dev=${p.did.slice(-6)} → ${label(r.ec)} ${r.uid ? 'uid=' + r.uid : ''} ${r.desc || ''}`);
    if (r.ec === 7) {
      // rotate device_id KHÁC (cách mới) → login lại
      poolIdx++;
      const p2 = POOL[poolIdx % POOL.length];
      console.log(`     ↻ ec7 → đổi device_id ${p2.did.slice(-6)} rồi login lại...`);
      const r2 = await tryLogin(user, pass, p2);
      console.log(`     ↻ dev=${p2.did.slice(-6)} → ${label(r2.ec)} ${r2.uid ? 'uid=' + r2.uid : ''} ${r2.desc || ''}`);
    }
    await sleep(1500);
  }
}
console.log('\n✔ done');
