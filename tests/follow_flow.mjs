// follow_flow.mjs — LUỒNG FOLLOW no-phone hoàn chỉnh.
//   Mỗi account: forge device → login (2135 full: send_code→code_login→2135→authenticate→re-login #17) → session
//                → resolve sec_uid target (aweme search) → follow → VERIFY stick (re-search follow_status).
//   Chạy dưới lớp t_full_session.mjs (đã proven login+follow+verify). Mỗi account 1 proxy riêng, xoay vòng.
//
//   node re/tests/follow_flow.mjs <target_uniqueId> [type=1|0] [--acc <file>] [--proxy <file>] [--conc N]
//     accounts file: mỗi dòng "user|pass|email|mailpass"
//     proxies file : mỗi dòng "ip:port:user:pass"  (rỗng = đi thẳng, KHÔNG khuyến nghị)
//   env: OMO_API_KEY (captcha send_code), RE_VER (mặc định 45.7.3)
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(DIR, '..', '..');
const args = process.argv.slice(2);
const target = (args[0] || '').replace(/^@/, '');
if (!target) { console.error('cần <target_uniqueId>. VD: node re/tests/follow_flow.mjs idmahg 1 --acc accounts.txt --proxy proxies.txt'); process.exit(1); }
const type = /^[01]$/.test(args[1]) ? args[1] : '1';
const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const accFile = flag('--acc', path.join(DIR, 'accounts.txt'));
const proxyFile = flag('--proxy', path.join(DIR, 'proxies.txt'));
const conc = parseInt(flag('--conc', '2'), 10);
const OMO = process.env.OMO_API_KEY || '';

if (!fs.existsSync(accFile)) { console.error('không thấy accounts file: ' + accFile + '  (mỗi dòng user|pass|email|mailpass)'); process.exit(1); }
const accounts = fs.readFileSync(accFile, 'utf8').trim().split('\n').map((l) => l.trim()).filter(Boolean);
const proxies = fs.existsSync(proxyFile)
  ? fs.readFileSync(proxyFile, 'utf8').trim().split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const [ip, port, u, p] = l.split(':'); return u ? `http://${u}:${p}@${ip}:${port}` : `http://${ip}:${port}`; })
  : [];

console.log(`[follow_flow] ${accounts.length} account → follow @${target} (type=${type}) | ${proxies.length} proxy | conc=${conc}`);

function runOne(account, idx) {
  return new Promise((resolve) => {
    const proxy = proxies.length ? proxies[idx % proxies.length] : '';
    const user = account.split('|')[0];
    const env = { ...process.env, FOLLOW: target, FOLLOW_TYPE: type, RE_VER: process.env.RE_VER || '45.7.3', NO_COMPILE: '1', OMO_API_KEY: OMO };
    if (proxy) env.PROXY = proxy;
    const p = spawn(process.execPath, [path.join(DIR, 't_full_session.mjs'), account], { env, cwd: ROOT });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', () => {});
    const to = setTimeout(() => { try { p.kill(); } catch {} }, 260000);
    p.on('close', () => {
      clearTimeout(to);
      const session = /🎉🎉🎉 SESSION!/.test(out);
      const uid = (out.match(/user_id=(\d+)/) || [])[1];
      const followSc = (out.match(/\[F2\][^\n]*status_code=(-?\d+)/) || [])[1];
      const after = (out.match(/follow_status\(after\)=(\d+)/) || [])[1];
      const ec = (out.match(/user\/login=\s*(\d+)/) || [])[1];
      const stuck = after === '1';
      const status = !session ? (ec === '7' ? 'ec7(throttle/IP)' : 'login-fail(' + (ec || '?') + ')') : (followSc === '0' ? (stuck ? '✅ STUCK' : '⚠️ shadow-drop') : 'follow-fail(' + (followSc || '?') + ')');
      console.log(`  [${idx + 1}/${accounts.length}] ${user} | proxy ${proxy ? proxy.split('@')[1] : 'direct'} → ${session ? 'SESSION ' + (uid || '') : 'NO-SESSION'} | follow: ${status}`);
      resolve({ user, uid, session, followSc, after, stuck, status });
    });
  });
}

(async () => {
  const results = [];
  for (let i = 0; i < accounts.length; i += conc) {
    const batch = accounts.slice(i, i + conc).map((a, j) => runOne(a, i + j));
    results.push(...await Promise.all(batch));
  }
  const stuck = results.filter((r) => r.stuck).length;
  const shadow = results.filter((r) => r.session && r.followSc === '0' && !r.stuck).length;
  const nologin = results.filter((r) => !r.session).length;
  console.log('\n===== TỔNG KẾT follow @' + target + ' =====');
  console.log(`✅ STUCK (follow thật): ${stuck}/${results.length}  |  ⚠️ shadow-drop: ${shadow}  |  ❌ no-session: ${nologin}`);
  results.forEach((r) => console.log(`  ${r.user} → ${r.status}${r.uid ? ' (uid ' + r.uid + ')' : ''}`));
})();
