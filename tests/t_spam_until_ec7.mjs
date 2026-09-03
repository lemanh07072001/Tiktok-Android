// Spam 1 account LIÊN TỤC tới khi ra ec7 → rotate device_id (pool khác) → login lại, xem có qua không.
//  Tối ưu: chỉ dsign + userLogin (bỏ warmup/preCheck) → 2 JVM/login. Feed device-state.
//  Env: RU/RP account; MAX số lần (default 40).
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, seedCookies } from '../src/login.mjs';

const POOL = [
  { did: '7665624514735244821', iid: '7665628081449109268', oud: 'c0c0ba3f5d16f614', gaid: 'b13dc71a-a0d0-4509-8450-dae659764fbb', state: 'msstate_7665624' },
  { did: '7665549046120433172', iid: '7665552654689339157', oud: '9fad4e30b02dbdda', gaid: '', state: 'msstate_7665549' },
];
const ATTK = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk';
const USER = process.env.RU || 'user8146217183232', PASS = process.env.RP || '@JuVaNIQGOB58';
const MAX = Number(process.env.MAX || 40);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const label = ec => ec === 7 ? '❌ec7' : ec === 2135 ? '✅2135' : ec === 1108 ? '✅1108' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅SUCCESS' : ec === 1105 ? '⚠️captcha' : 'ec' + ec;

function useDevice(p) {
  process.env.MSB_DEVSTATE_DIR = `${ATTK}/${p.state}`;
  Object.assign(process.env, { MS_VENDOR: 'libs_trill/', MS_LIBS: 'libs_trill', MS_SIGN_OFF: '0x9ecc0', MS_DISP_OFF: '0x11a1e0',
    MS_LICENSE_FILE: 'license_mus4573.json', MSB_VER: '45.7.3', MSB_VERCODE: '2024507030', MSB_FULLINIT: '1', MSB_KV: '1', APP_VER: '45.7.3', APP_VC: '2024507030' });
  return { device_id: p.did, install_id: p.iid, id: { openudid: p.oud, cdid: '00000000-0000-4000-8000-000000000001', clientudid: '00000000-0000-4000-8000-000000000002', google_aid: p.gaid || '00000000-0000-4000-8000-000000000000' } };
}
async function login(p) {
  const dev = useDevice(p);
  const d = await dsign(dev).catch(e => ({ _err: e }));
  if (!d.device_token) return { ec: 'dsign-fail', err: d._err?.message };
  seedCookies(d.cookies || {});
  const r = await userLogin(USER, PASS, dev, d);
  return { ec: r.j?.data?.error_code ?? r.j?.message, uid: r.j?.data?.user_id_str, desc: (r.j?.data?.description || '').slice(0, 45) };
}

console.log(`SPAM ${USER} tới khi ec7 (MAX=${MAX})`);
let idx = 0, ec7count = 0;
for (let t = 1; t <= MAX; t++) {
  const p = POOL[0];
  const r = await login(p);
  console.log(`#${t} dev=${p.did.slice(-6)} → ${label(r.ec)} ${r.desc || ''}`);
  if (r.ec === 7) {
    ec7count++;
    const p2 = POOL[1];
    console.log(`  🎯 EC7! → rotate device_id=${p2.did.slice(-6)} rồi login lại...`);
    const r2 = await login(p2);
    console.log(`  ↻ dev=${p2.did.slice(-6)} → ${label(r2.ec)} ${r2.desc || ''}`);
    if (r2.ec !== 7) console.log(`  ✅ ROTATE CỨU ĐƯỢC ec7 (${label(r2.ec)})`);
    else console.log(`  ❌ rotate cũng ec7 → throttle rộng`);
    break;  // ra ec7 rồi thì dừng để báo cáo
  }
  await sleep(1200);
}
if (!ec7count) console.log(`\n✔ ${MAX} lần KHÔNG ra ec7 (feed device-state → login luôn qua)`);
