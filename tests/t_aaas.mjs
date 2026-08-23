// t_aaas.mjs — TEST DỨT ĐIỂM: aaas verify EMAIL pure-API (oracle x-argus) cho account FLAGGED.
//   device 7632 (phone thật, khớp oracle) + METASEC_ORACLE toàn luồng. combo 6-field.
//   Nếu authVerify 200 success → aaas EMAIL pure-API QUA (no-webview!). Nếu ec4 → cần genuine seal / CDP-drive.
// CHIỀU ĐÚNG (ground-truth): login PASSWORD → verify EMAIL (type 2). (login email-code → verify password type 3 = khó).
import fs from 'node:fs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin } from '../src/login.mjs';
import { challenges, authSend, authVerify, newPseudoId } from '../src/aaas.mjs';
import { cookieHdr } from '../src/login.mjs';
import * as hot from '../../mobile/hotmail.mjs';

// RE_DEV="device_id|install_id" (mặc định phone 7632). Oracle optional: có→x-argus genuine (chỉ khớp 7632); không→unidbg.
console.log('[*] x-argus:', process.env.METASEC_ORACLE ? 'ORACLE (chỉ đúng device 7632)' : 'UNIDBG (offline, khớp mọi device)');
const f = fs.readFileSync(process.argv[2] || 'mobile/tg/_acc4618_combo.txt', 'utf8').trim().split('\n')[0].split('|');
const user = f[0], pass = f[1], email = f[2], hotCombo = [f[2], f[1], f[4], f[5]].join('|');
const [DID, IID] = (process.env.RE_DEV || '7632162877655729682|7654446515603801877').split('|');
const dev = { device_id: DID, install_id: IID, id: { openudid: 'o', cdid: 'c', google_aid: 'g' } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const p = hot.parseCombo(hotCombo);
const { access_token } = await hot.getAccessToken(p);
const seen = new Set();
try { const pre = await hot.fetchTikTokCode({ email, access_token }); if (pre?.code) seen.add(pre.code); } catch {}
console.log('[1] hotmail OK, baseline codes:', [...seen]);

const d = await dsign(dev);
console.log('[2] dsign s=%s (device 7632 + oracle)', d.s);
await warmup(dev, d);

// pre_check + PASSWORD login → kỳ vọng 2135 + aaas_ticket (verify factor = EMAIL type 2)
const pc = await preCheck(user, dev, d);
console.log('[3] pre_check ec=%s', pc.j?.message);
const lg = await userLogin(user, pass, dev, d);
const ec = lg.j?.data?.error_code;
console.log('[5] password login ec=%s', ec ?? lg.j?.message);
if (lg.j?.message === 'success') { console.log('🎉 login SUCCESS luôn (account không cần aaas)!'); process.exit(0); }
let dl;
// note 19: ticket + pseudo_id ở HEADER x-tt-verify-idv-decision-conf (lg.dc), KHÔNG ở body
const ticket = lg.dc?.passport_ticket || lg.j?.data?.aaas_ticket;
if (ec !== 2135 || !ticket) { console.log('   ❌ không phải 2135+ticket (dc=%s):', JSON.stringify(lg.dc || '').slice(0, 80), (lg.txt || '').slice(0, 120)); process.exit(1); }
console.log('[5] 2135 passport_ticket=%s (từ header)', ticket.slice(0, 20));
const xtt = lg.xtt || '';

// ── aaas verify EMAIL ── pseudo_id THẬT từ header extra[] (email factor type 2), KHÔNG bịa
const ch = await challenges(dev, d, ticket, xtt);
console.log('[6] challenges ec=%s factors=%s', ch.ec, JSON.stringify(ch.j?.data?.challenges || ch.j?.data));
const emailFactor = (lg.dc?.extra || []).find((e) => e.type === 2);
const pid = emailFactor?.pseudo_id || newPseudoId();
console.log('[7] pseudo_id=%s %s', pid, emailFactor ? '(THẬT từ header)' : '(bịa — fallback)');
const asend = await authSend(dev, d, ticket, pid, '');   // ground-truth: KHÔNG x-tt-token
console.log('[7c] authenticate SEND (action=3) http=%s ec=%s %s', asend.status, asend.ec, (asend.txt || '').slice(0, 90));

console.log('[8] chờ VERIFY code…'); await sleep(9000);
let vcode = null; dl = Date.now() + 110000;
while (Date.now() < dl) { try { const h = await hot.fetchTikTokCode({ email, access_token }); if (h?.code && !seen.has(h.code)) { vcode = h.code; break; } } catch {} process.stdout.write('.'); await sleep(4000); }
console.log(); if (!vcode) { console.log('❌ no verify code'); process.exit(3); }
console.log('[8] VERIFY CODE =', vcode);

const au = await authVerify(dev, d, ticket, pid, vcode, '');
console.log('[9] authenticate VERIFY (action=4) http=%s ec=%s %s', au.status, au.ec, (au.txt || '').slice(0, 120));

console.log('\n=== KẾT LUẬN ===');
if (au.j?.message === 'success') {
  console.log('🎉🎉🎉 AAAS EMAIL PURE-API QUA! (oracle x-argus, no-webview). Re-login lấy session…');
  const re = await userLogin(user, pass, dev, d);   // re-password-login (risk flag đã clear)
  console.log('[10] re-login ec=%s', re.j?.data?.error_code ?? re.j?.message);
  if (re.j?.message === 'success') { const uid = re.j?.data?.user_id_str || re.j?.data?.user_id; const s = { cookie: cookieHdr(), deviceId: dev.device_id, iid: dev.install_id, xtt: re.xtt || '', uid, ts: Date.now() }; fs.mkdirSync('re/out', { recursive: true }); fs.writeFileSync(`re/out/session_${uid || email}.json`, JSON.stringify(s, null, 2)); console.log('  💾 session saved uid=%s', uid); }
} else if (au.ec === 4) {
  console.log('❌ ec=4 → x-argus genuine + s=0 CHƯA đủ cho EMAIL authenticate ⇒ cần device_token s:1 GENUINE (hoặc CDP-drive webview).');
} else {
  console.log('? ec=%s → %s', au.ec, (au.txt || '').slice(0, 150));
}
