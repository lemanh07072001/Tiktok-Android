// t_register_trust.mjs — Trust-gate SẠCH: tạo account MỚI (mail.tm) trên device RE_DEV.
//  register-account chỉ success trên device TRUSTED; untrusted => ec7/2100 ở send_code/register, hoặc không gửi mail.
//  Không dính account-rate-limit (email tươi). Tự chủ (mail.tm không cần key/combo).
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup } from '../src/login.mjs';
import { checkEmailRegistered, sendVerifyCode, registerVerifyLogin } from '../src/account.mjs';
import * as mt from '../../mobile/mailtm.mjs';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const [DID, IID] = (process.env.RE_DEV || '').split('|');
const dev = { device_id: DID, install_id: IID, id: { openudid: process.env.OUD || 'o', cdid: process.env.CDID || 'c', google_aid: process.env.GAID || 'g' } };
const log = (...a) => console.log(...a);
try {
  const d = await dsign(dev); log('dsign s=%s token=%s', d.s, !!d.device_token);
  await warmup(dev, d).catch(() => {});
  const acc = await mt.createAccount(); log('mailtm addr=%s', acc.address);
  const ce = await checkEmailRegistered(dev, d, acc.address); log('check_email ec=%s msg=%s', ce.ec, ce.j?.message);
  if (ce.ec === 1105) { log('⚠️ CAPTCHA at check_email (risk)'); process.exit(3); }
  const sv = await sendVerifyCode(dev, d, acc.address); log('send_code ec=%s msg=%s txt=%s', sv.ec, sv.j?.message, (sv.txt || '').slice(0, 120));
  const svEc = sv.ec;
  if (svEc === 7 || svEc === 2100 || svEc === 34) { log('❌ UNTRUSTED tại send_code ec=%s', svEc); process.exit(7); }
  if (sv.j?.message !== 'success') { log('❌ send_code không success => untrusted/email-blocked'); process.exit(7); }
  const { token } = await mt.getToken({ address: acc.address, password: acc.password });
  let code = null;
  for (let i = 0; i < 40; i++) { process.stdout.write('.'); const h = await mt.fetchTikTokCode({ token }); if (h?.code) { code = h.code; break; } await sleep(2500); }
  log();
  if (!code) { log('⚠️ KHÔNG nhận mail => untrusted (không gửi mail) HOẶC mail.tm bị TikTok chặn'); process.exit(3); }
  log('code=%s', code);
  const reg = await registerVerifyLogin(dev, d, acc.address, acc.password, code);
  log('register ec=%s msg=%s uid=%s', reg.ec, reg.j?.message, reg.j?.data?.user_id_str || reg.j?.data?.user_id || '');
  if (reg.j?.message === 'success') { log('🎉 REGISTER SUCCESS => DEVICE %s TRUSTED (Shamiko+official thắng metasec)', DID); process.exit(0); }
  log('❌ REGISTER FAIL ec=%s => UNTRUSTED txt=%s', reg.ec, (reg.txt || '').slice(0, 160)); process.exit(7);
} catch (e) { log('ERR %s', e.message); process.exit(3); }
