// t_register_outlook.mjs — Trust-gate SẠCH bằng mailbox THẬT (outlook) còn sống.
//  Dùng COMBO email vừa làm email đăng ký vừa làm hộp thư đọc mã (code gửi về chính nó).
//  register-account success = device RE_DEV TRUSTED; untrusted => ec7/2100/34 ở send_code/register.
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup } from '../src/login.mjs';
import { checkEmailRegistered, sendVerifyCode, registerVerifyLogin } from '../src/account.mjs';
import * as hot from '../../mobile/hotmail.mjs';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const combo = process.env.COMBO;
const email = combo.split('|')[0];
const tiktokPass = 'Rt' + Math.random().toString(36).slice(2, 10) + '!9';
const [DID, IID] = (process.env.RE_DEV || '').split('|');
const dev = { device_id: DID, install_id: IID, id: { openudid: process.env.OUD || 'o', cdid: process.env.CDID || 'c', google_aid: process.env.GAID || 'g' } };
try {
  const d = await dsign(dev); console.log('dsign s=%s token=%s', d.s, !!d.device_token);
  await warmup(dev, d).catch(() => {});
  const p = hot.parseCombo(combo); const { access_token } = await hot.getAccessToken(p);
  const ce = await checkEmailRegistered(dev, d, email);
  console.log('check_email ec=%s msg=%s is_registered=%s', ce.ec, ce.j?.message, ce.j?.data?.is_registered);
  if (ce.j?.data?.is_registered) { console.log('❌ email đã đăng ký TikTok -> không tạo mới trên device này'); process.exit(3); }
  if (ce.ec === 1105) { console.log('⚠️ captcha at check'); process.exit(3); }
  const sv = await sendVerifyCode(dev, d, email);
  console.log('send_code ec=%s msg=%s txt=%s', sv.ec, sv.j?.message, (sv.txt || '').slice(0, 120));
  if (sv.ec === 7 || sv.ec === 2100 || sv.ec === 34) { console.log('❌ UNTRUSTED at send_code ec=%s', sv.ec); process.exit(7); }
  if (sv.j?.message !== 'success') { console.log('❌ send_code không success'); process.exit(7); }
  let code = null;
  for (let i = 0; i < 45; i++) { process.stdout.write('.'); try { const h = await hot.fetchTikTokCode({ email, access_token }); if (h?.code && /^\d{6}$/.test(h.code)) { code = h.code; break; } } catch {} await sleep(2500); }
  console.log();
  if (!code) { console.log('❌ no code received'); process.exit(3); }
  console.log('code=%s', code);
  const reg = await registerVerifyLogin(dev, d, email, tiktokPass, code);
  console.log('register ec=%s msg=%s uid=%s', reg.ec, reg.j?.message, reg.j?.data?.user_id_str || reg.j?.data?.user_id || '');
  if (reg.j?.message === 'success') { console.log('🎉 REGISTER SUCCESS => DEVICE %s TRUSTED (Shamiko+official thắng metasec)', DID); process.exit(0); }
  console.log('❌ REGISTER FAIL ec=%s => UNTRUSTED txt=%s', reg.ec, (reg.txt || '').slice(0, 160)); process.exit(7);
} catch (e) { console.log('ERR %s', e.message); process.exit(3); }
