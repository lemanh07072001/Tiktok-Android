// re/tests/t_createaccount.mjs — Device-association: create fresh account on minted device → login SUCCESS
// Usage: RE_DEV="device_id|install_id" node re/tests/t_createaccount.mjs <hotmail_combo>
// Example: RE_DEV="7654265922945893909|..." node re/tests/t_createaccount.mjs "acc@hotmail.com|pass|..."
import '../src/net.mjs';
import fs from 'node:fs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin } from '../src/login.mjs';
import { genEmail, checkEmailRegistered, sendVerifyCode, registerVerifyLogin } from '../src/account.mjs';
import { cookieHdr } from '../src/login.mjs';
import * as hot from '../../mobile/hotmail.mjs';

const [DID, IID] = (process.env.RE_DEV || '7654265922945893909|7654515472762717972').split('|');
const dev = { device_id: DID, install_id: IID, id: { openudid: 'o', cdid: 'c', google_aid: 'g' } };
const emailCombo = process.argv[2] || 'ltnvicvy3742@hotmail.com|...';  // user|pass|... (see mobile/tg/...)
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

console.log('🚀 DEVICE-ASSOCIATION: Create account on minted device\n');
console.log('📱 Device ID:', dev.device_id);

try {
  // [1] Setup device
  console.log('\n[1] Device setup...');
  const d = await dsign(dev);
  console.log('    dsign s=%s ✓', d.s);
  await warmup(dev, d);
  console.log('    warmup ✓');

  // [2] Generate fresh email
  const email = genEmail();
  const password = Math.random().toString(36).slice(2, 12);
  console.log('\n[2] Generated credentials');
  console.log('    email:', email);
  console.log('    password: [generated]');

  // [3] Check email registered
  console.log('\n[3] Checking email...');
  const ce = await checkEmailRegistered(dev, d, email);
  console.log('    Status:', ce.status, '| EC:', ce.ec ?? ce.j?.message);
  if (ce.ec === 1105) {
    console.log('    ⚠️  Captcha required — email check blocked');
    process.exit(1);
  }
  if (ce.j?.message !== 'success') {
    console.log('    ❌ Email check failed:', (ce.txt || '').slice(0, 150));
    process.exit(1);
  }

  // [4] Send verify code
  console.log('\n[4] Sending verify code...');
  const sv = await sendVerifyCode(dev, d, email);
  console.log('    Status:', sv.status, '| EC:', sv.ec ?? sv.j?.message);
  if (sv.ec === 1105) {
    console.log('    ⚠️  Captcha required — code send blocked');
    process.exit(1);
  }
  if (sv.j?.message !== 'success') {
    console.log('    ❌ Send code failed:', (sv.txt || '').slice(0, 150));
    process.exit(1);
  }

  // [5] Wait + read code from email
  console.log('\n[5] Reading verification code...');
  const [emAddr, emPass, ...emRest] = emailCombo.split('|');
  const p = hot.parseCombo(emailCombo);
  const { access_token } = await hot.getAccessToken(p);

  let verifyCode = null;
  let retries = 30;
  while (!verifyCode && retries-- > 0) {
    try {
      process.stdout.write('.');
      const h = await hot.fetchTikTokCode({ email, access_token });
      if (h?.code && /^\d{6}$/.test(h.code)) {
        verifyCode = h.code;
        break;
      }
    } catch {}
    await sleep(2000);
  }
  console.log();
  if (!verifyCode) {
    console.log('    ❌ No verify code received (check hotmail combo)');
    process.exit(1);
  }
  console.log('    ✓ Code:', verifyCode);

  // [6] Register account
  console.log('\n[6] Registering account...');
  const reg = await registerVerifyLogin(dev, d, email, password, verifyCode);
  console.log('    Status:', reg.status, '| EC:', reg.ec ?? reg.j?.message);
  if (reg.j?.message !== 'success') {
    console.log('    ❌ Registration failed:', (reg.txt || '').slice(0, 150));
    process.exit(1);
  }
  const uid = reg.j?.data?.user_id || reg.j?.data?.user_id_str;
  console.log('    🎉 Account created: UID=%s', uid);

  // [7] Login (should be SUCCESS, no 2135)
  console.log('\n[7] Login to device-associate...');
  const lg = await userLogin(email, password, dev, d);
  const ec = lg.j?.data?.error_code;
  console.log('    Status:', lg.status, '| EC:', ec ?? lg.j?.message);

  if (lg.j?.message === 'success') {
    console.log('    🎉 LOGIN SUCCESS (no-phone device-association proven!)');
    const uid2 = lg.j?.data?.user_id_str || lg.j?.data?.user_id;
    const s = {
      email, password, device: dev.device_id, iid: dev.install_id,
      cookie: cookieHdr(), xtt: lg.xtt || '', uid: uid2, ts: Date.now()
    };
    fs.mkdirSync('re/out', { recursive: true });
    fs.writeFileSync(`re/out/session_${uid2 || email}.json`, JSON.stringify(s, null, 2));
    console.log('    💾 session saved');
  } else if (ec === 2135) {
    console.log('    ⚠️  Got 2135 (unexpected for fresh account) — needs aaas verify');
  } else {
    console.log('    ❌ Login failed');
    process.exit(1);
  }

} catch (err) {
  console.log('\n❌ Error:', err.message);
  console.log(err.stack);
  process.exit(1);
}
