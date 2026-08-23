// t_emaillogin.mjs — TEST: login account FLAGGED bằng email-code (bỏ qua 2135) trên device trusted.
//   Đóng tường 2135. Combo 6-field: user|pass|email|emailpass|refresh|client_id.
//   RE_DEV="device_id|install_id" (trusted). UNIDBG (no phone).
import fs from 'node:fs';
import { dsign, newIdentity } from '../src/device.mjs';
import { warmup, JAR } from '../src/login.mjs';
import { sendCode, codeLogin, availableWays, sessionFrom } from '../src/login_email.mjs';
import { callAuthed } from '../src/session.mjs';
import * as hot from '../../mobile/hotmail.mjs';

const comboFile = process.argv[2] || 'mobile/tg/_acc4618_combo.txt';
const f = fs.readFileSync(comboFile, 'utf8').trim().split('\n')[0].split('|');
const email = f[2], hotCombo = [f[2], f[1], f[4], f[5]].join('|');
const [DID, IID] = (process.env.RE_DEV || '7654265922945893909|7654267846919063317').split('|');
const dev = { device_id: DID, install_id: IID, id: newIdentity() };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

console.log('[email-login] account email=%s | device=%s (UNIDBG)', email, DID);

// hotmail token + baseline (code cũ để bỏ qua)
const p = hot.parseCombo(hotCombo);
const { access_token } = await hot.getAccessToken(p);
console.log('[1] hotmail token OK');
const seen = new Set();
try { const pre = await hot.fetchTikTokCode({ email, access_token }); if (pre?.code) { seen.add(pre.code); console.log('[1] baseline code cũ:', pre.code); } } catch {}

// dsign + warmup trên trusted device
const d = await dsign(dev);
console.log('[2] dsign s=%s', d.s);
await warmup(dev, d);

// send_code
let sc = await sendCode(email, dev, d);
console.log('[3] send_code ec=%s ticket=%s %s', sc.j?.data?.error_code ?? sc.ec, sc.j?.data?.passport_ticket ? '✓' : '✗', (sc.txt || '').slice(0, 80));
if (sc.ec === 1105) { console.log('   ⚠️ 1105 = captcha (device này cần OMO solve — chưa wire ở test). Dừng.'); process.exit(2); }
if (sc.j?.message !== 'success') { console.log('   ❌ send_code fail:', (sc.txt || '').slice(0, 150)); process.exit(1); }
const pt = sc.j?.data?.passport_ticket;
if (pt) { const aw = await availableWays(dev, d, pt); console.log('[3b] available_ways ec=%s', aw.ec); }

// đọc code mới
console.log('[4] chờ code email (tối đa 120s)…');
let code = null; const deadline = Date.now() + 120000;
await sleep(8000);
while (Date.now() < deadline) {
  try { const hit = await hot.fetchTikTokCode({ email, access_token }); if (hit?.code && !seen.has(hit.code)) { code = hit.code; break; } } catch {}
  process.stdout.write('.'); await sleep(4000);
}
console.log();
if (!code) { console.log('❌ không nhận được code mới'); process.exit(3); }
console.log('[4] CODE =', code);

// code_login
const lg = await codeLogin(email, code, dev, d);
const ec = lg.j?.data?.error_code;
console.log('[5] code_login ec=%s %s', ec ?? lg.j?.message, (lg.txt || '').slice(0, 100));

console.log('\n=== KẾT LUẬN ===');
if (lg.j?.message === 'success' || (lg.j?.data && !ec)) {
  const session = sessionFrom(lg, dev);
  fs.mkdirSync('re/out', { recursive: true });
  const out = `re/out/session_${session.uid || email}.json`;
  fs.writeFileSync(out, JSON.stringify(session, null, 2));
  console.log('🎉🎉 EMAIL-CODE LOGIN SUCCESS (account FLAGGED, no-phone)! uid=%s → %s', session.uid, out);
  const info = await callAuthed(session, '/passport/account/info/').catch(() => ({ status: 0 }));
  console.log('  ✅ account/info http=%s msg=%s', info.status, info.j?.message);
} else if (ec === 2135) {
  console.log('⚠️ code_login vẫn 2135 (account cần password-verify webview — bất khả pure-API, xem aaas-2135-reversal).');
} else {
  console.log('? ec=%s', ec);
}
