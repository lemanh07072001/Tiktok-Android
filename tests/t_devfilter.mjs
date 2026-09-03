// t_devfilter.mjs — TEST RỘNG: quét pool minted device × account, đo tỉ lệ SUCCESS/ec7/2135.
//   Chứng minh cơ chế device-filter cho no-phone scale. UNIDBG (không phone lúc ký).
//   Dùng: node re/tests/t_devfilter.mjs   (accounts + devices hardcode bên dưới, đọc thêm từ file)
import fs from 'node:fs';
import { dsign, newIdentity } from '../src/device.mjs';
import { warmup, preCheck, userLogin, seedCookies, JAR, cookieHdr } from '../src/login.mjs';
import { callAuthed } from '../src/session.mjs';

// accounts test (user|pass)
const ACCOUNTS = (process.env.RE_ACCOUNTS || [
  'user7785224835733|@K4a#XIGjeM0xo',
  'user2566145822112|@K4a#WR2iLg8j2',
  'user4618525494140|@K4a@OhHctwB9',
].join(',')).split(',').filter(Boolean);

// pool device minted (device_id|install_id) — lấy N con đầu regbox/minted_devices.txt
const N = Number(process.env.RE_NDEV || 8);
let POOL = [];
try {
  POOL = fs.readFileSync('regbox/minted_devices.txt', 'utf8').trim().split('\n')
    .map(l => l.trim()).filter(Boolean).slice(0, N)
    .map(l => { const [d, i] = l.split('|'); return { device_id: d, install_id: i }; });
} catch (e) { console.error('không đọc được minted_devices.txt:', e.message); process.exit(1); }

console.log(`[devfilter] ${ACCOUNTS.length} account × ${POOL.length} device (UNIDBG no-phone)\n`);

// reset JAR giữa các lần (module-scope) — dùng seedCookies để clear phần login-state
function freshJar() { for (const k of Object.keys(JAR)) delete JAR[k]; JAR['store-idc'] = 'alisg'; JAR['tt-target-idc'] = 'alisg'; }

async function tryLogin(acc, dv) {
  const [user, pass] = acc.split('|');
  freshJar();
  const dev = { device_id: dv.device_id, install_id: dv.install_id, id: newIdentity() };
  const d = await dsign(dev).catch(e => { throw new Error('dsign ' + e.message); });
  await warmup(dev, d);
  const pc = await preCheck(user, dev, d);
  if (pc.j?.message !== 'success') return { r: 'precheck_fail', ec: pc.j?.data?.error_code };
  const lg = await userLogin(user, pass, dev, d);
  const ec = lg.j?.data?.error_code;
  if (lg.j?.message === 'success' || (lg.j?.data && !ec)) {
    const uid = lg.j?.data?.user_id_str || lg.j?.data?.user_id || '';
    const session = { cookie: cookieHdr(), deviceId: dev.device_id, iid: dev.install_id, xtt: lg.xtt || '', uid, user, ts: Date.now() };
    fs.mkdirSync('re/out', { recursive: true });
    fs.writeFileSync(`re/out/session_${uid || user}.json`, JSON.stringify(session, null, 2));
    // verify authenticated
    const info = await callAuthed(session, '/passport/account/info/').catch(() => ({ status: 0 }));
    return { r: 'SUCCESS', uid, s: d.s, verify: info.j?.message === 'success' ? 'ok200' : `http${info.status}` };
  }
  if (ec === 2135 || ec === 2136) return { r: '2135_verify', s: d.s };
  if (ec === 7) return { r: 'ec7', s: d.s };
  return { r: 'ec' + ec, s: d.s };
}

const devStat = {};   // device_id → kết quả gần nhất (đo good/bad)
for (const acc of ACCOUNTS) {
  const user = acc.split('|')[0];
  console.log(`\n### ${user}`);
  let won = false;
  for (const dv of POOL) {
    let out; try { out = await tryLogin(acc, dv); } catch (e) { out = { r: 'ERR:' + e.message.slice(0, 40) }; }
    devStat[dv.device_id] = out.r;
    const tag = out.r === 'SUCCESS' ? `✅ SUCCESS uid=${out.uid} verify=${out.verify}` : out.r;
    console.log(`  ${dv.device_id.slice(-6)}  s=${out.s ?? '-'}  → ${tag}`);
    if (out.r === 'SUCCESS') { won = true; break; }   // account này xong, sang account kế
  }
  if (!won) console.log('  ⚠️ không con device nào cho account này SUCCESS (mọi con ec7/verify/err)');
}

const good = Object.values(devStat).filter(r => r === 'SUCCESS').length;
console.log(`\n=== TỔNG: ${good}/${Object.keys(devStat).length} device chạm SUCCESS ít nhất 1 lần ===`);
