// ĐĂNG KÝ account TikTok trên device_id MỚI (Widevine-rotated trusted) + email combo → device-association → login SUCCESS.
// Usage: PROXY_URL=... node re/tests/t_signup_newdev.mjs
import '../src/net.mjs';
import fs from 'node:fs';
import { dsign } from '../src/device.mjs';
import { warmup, userLogin, cookieHdr } from '../src/login.mjs';
import { checkEmailRegistered, sendVerifyCode, registerVerifyLogin } from '../src/account.mjs';
import * as hot from '../../mobile/hotmail.mjs';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// device_id MỚI (Widevine L3 reset + rotate) — TRUSTED (check_email=success)
const dev = {
  device_id: '7665624514735244821', install_id: '7665628081449109268',
  id: { openudid: 'c0c0ba3f5d16f614', cdid: '00000000-0000-4000-8000-000000000001',
        clientudid: '00000000-0000-4000-8000-000000000002', google_aid: 'b13dc71a-a0d0-4509-8450-dae659764fbb' },
};
const combo = 'pola_schis.wi@outlook.com|Lnanne122p|M.C550_BL2.0.U.MsaArtifacts.-Ch2WxMilTQazEKUgPbO2IFvX54*lG!kwmLXmCPuGgwxEEiWbLzLu1sg6x9rLEq*HeGWMxTmc3vEh8i9Vt*!Pqz4H7QTwNBvhmMsl6d90aDHwG6FKmTtOGZzV0fcUrHD3NqTF56S!mWzp45sUfkfhEVUvs4EOZKMIWkiXMCIfCSdtiHBhDetga*Xvhk6WCw8KLtcAcQaA3mBXOfY!IAEcOWmr203qFrcU3WsDVfJ*bxscLAmuvmr7lTJLC6vA*dqhn4lp4LY0Bhf3YdqmC6e262giuFqc4G8E64m8y*GbjFhNgBJURrKUodJ88JCVnIP4LZZxR!SIzGE9uTADPzfGdLLTsHnNZmY!nCmf96cXFfsYq6RwaVNZiZSe81!t2XmnztwfXGvl8*5joJQvzq2eRfmjmyHYJktqkq*9zVb6RLqKdJfaUIRqlNYZbWOvwaioDw$$|9e5f94bc-e8a4-4e73-b8be-63364c29d753';
const email = process.env.NEWMAIL || combo.split('|')[0];
const password = 'Tk' + Math.random().toString(36).slice(2, 9) + '@9';

console.log('📱 device_id MỚI:', dev.device_id, '| email:', email);
const d = await dsign(dev); console.log('[1] dsign s=%s ✓', d.s);
await warmup(dev, d).catch(() => {});
const ce = await checkEmailRegistered(dev, d, email);
console.log('[2] check_email status=%s ec=%s', ce.status, ce.ec ?? ce.j?.message);
if (ce.ec === 1105) { console.log('❌ captcha'); process.exit(1); }
if (ce.j?.data?.is_registered) { console.log('⚠️ email ĐÃ đăng ký TikTok → chuyển sang login trực tiếp'); }
const sv = await sendVerifyCode(dev, d, email);
console.log('[3] send_code status=%s ec=%s', sv.status, sv.ec ?? sv.j?.message);
if (sv.ec === 1105) { console.log('❌ captcha at send_code'); process.exit(1); }

console.log('[4] đọc code từ email...');
const p = hot.parseCombo(combo); const { access_token } = await hot.getAccessToken(p);
let code = null, tries = 40;
while (!code && tries-- > 0) { process.stdout.write('.'); try { const h = await hot.fetchTikTokCode({ email, access_token }); if (h?.code && /^\d{6}$/.test(h.code)) { code = h.code; break; } } catch {} await sleep(2500); }
console.log();
if (!code) { console.log('❌ không nhận code'); process.exit(1); }
console.log('    code=%s', code);

const reg = await registerVerifyLogin(dev, d, email, password, code);
console.log('[5] register status=%s ec=%s msg=%s', reg.status, reg.ec ?? reg.j?.message, (reg.j?.data?.description || '').slice(0, 60));
const uid = reg.j?.data?.user_id_str || reg.j?.data?.user_id;
if (reg.j?.message === 'success') {
  console.log('    🎉 ACCOUNT TẠO: uid=%s pass=%s', uid, password);
  const lg = await userLogin(email, password, dev, d);
  console.log('[6] login ec=%s msg=%s', lg.j?.data?.error_code ?? lg.j?.message, lg.j?.message);
  if (lg.j?.message === 'success') {
    const s = { email, password, device: dev.device_id, iid: dev.install_id, cookie: cookieHdr(), xtt: lg.xtt || '', uid: lg.j?.data?.user_id_str || uid, ts: Date.now() };
    fs.mkdirSync('re/out', { recursive: true });
    fs.writeFileSync(`re/out/session_newdev_${s.uid}.json`, JSON.stringify(s, null, 2));
    console.log('    🎉🎉 LOGIN SUCCESS no-phone trên device_id MỚI — session saved re/out/session_newdev_%s.json', s.uid);
  } else console.log('    login ec=%s (2135=cần verify; success=xong)', lg.j?.data?.error_code);
} else {
  console.log('    register fail:', (reg.txt || JSON.stringify(reg.j || {})).slice(0, 200));
}
