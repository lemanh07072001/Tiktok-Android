// t_trust_check.mjs — TRUST GATE test sạch (không confound rate-limit như login):
//   check_email_registered → ec7 = device UNTRUSTED | success/1011 = TRUSTED.
//   Trả lời "device offline forge có trust không". Dùng default signer 45.0.x (coherent với forge 45.0.x).
import '../src/net.mjs';
import { registerDevice, newIdentity, dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';

const mode = process.argv[2] || 'saved';   // 'forge' = register mới | 'saved' = dùng untrusted_devreg.json
let dev;
if (mode === 'forge') {
  const id = newIdentity();
  const r = await registerDevice(id);
  console.log('[forge] device_register → device_id=%s new_user=%s', r.device_id, r.new_user);
  if (!r.device_id) { console.log('❌ device_register FAIL (proxy/IP?):', JSON.stringify(r).slice(0, 150)); process.exit(1); }
  dev = { device_id: r.device_id, install_id: r.install_id, id };
} else {
  const s = JSON.parse(fs.readFileSync('ground-truth/untrusted_devreg.json', 'utf8'));
  dev = { device_id: s.device_id, install_id: s.resp?.install_id_str || s.resp?.install_id, id: s.id };
  console.log('[saved-forge] device_id=%s (forge offline, new_user=%s)', dev.device_id, s.new_user);
}

const d = await dsign(dev).catch((e) => ({ _err: e }));
console.log('dsign → s=%s device_token=%s', d.s, d.device_token ? 'OK' : ('FAIL ' + (d._err?.message || '')));
if (!d.device_token) { console.log('❌ dsign fail (device blocked?)'); process.exit(1); }
seedCookies(d.cookies || {});

const email = 'chk' + crypto.randomBytes(4).toString('hex') + '@gmail.com';
const r = await passportCall(dev, d, '/passport/user/check_email_registered', {
  params: { account_sdk_source: 'app', multi_login: '1', email: enc(email), mix_mode: '1' },
});
const ec = r.j?.data?.error_code ?? r.j?.message;
console.log('\ncheck_email_registered → http=%s ec=%s', r.status, ec);
console.log('resp:', JSON.stringify(r.j?.data || r.j || r.txt?.slice(0, 200)).slice(0, 280));
console.log('\n=== KẾT LUẬN TRUST ===');
if (ec === 7) console.log('❌ ec7 → device offline forge UNTRUSTED (tường no-phone register vẫn đứng)');
else if (r.j?.message === 'success' || ec === 1011 || r.j?.data?.is_registered !== undefined) console.log('🎉 TRUSTED — device offline QUA trust gate! (đột phá)');
else console.log('? ec khác:', ec, '(điều tra: có thể IP/proxy confound)');
