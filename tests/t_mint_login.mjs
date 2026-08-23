// t_mint_login.mjs — GAP #3: test TRUST cua device vua mint (official app + props sach + rotation).
//   device_id/install_id doc tu phone; openudid = SSAID rotation. Ky OFFLINE (unidbg) — trust o device_id server-side.
//   Ket qua: 2135/success = TRUSTED (gap#3: genuine+clean-props -> trusted); ec7 = untrusted (hoac IP-confound).
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';

const combo = process.argv[2] || 'user28122299571120|@K4a@RWnq0RMO';
const [user, pass] = combo.split('|');

// device vua mint tren phone (official app, props sach, rotation)
const dev = {
  device_id: process.env.MINT_DID || '7664886719149999636',
  install_id: process.env.MINT_IID || '7664888112582149909',
  id: {
    openudid: process.env.MINT_OPENUDID || 'a876a4163309fc9e',   // = SSAID rotation
    cdid: process.env.MINT_CDID || crypto.randomUUID(),
    clientudid: crypto.randomUUID(),
    google_aid: 'a9ca01d6-6e61-4d00-84d2-6ae037656dfd',           // = GAID rotation
  },
};
console.log('[mint-login] device=%s iid=%s openudid=%s', dev.device_id, dev.install_id, dev.id.openudid);
console.log('  x-argus source = UNIDBG offline. Trust o device_id server-side (mint boi official app).');

const d = await dsign(dev);
console.log('  dsign s=%s (device-guard; =1 binh thuong)', d.s);
seedCookies(dev.cookies || {});
try { await warmup(dev, d); } catch (e) { console.log('  warmup:', e.message); }
const pc = await preCheck(user, dev, d);
console.log('  pre_check ec=%s', pc.j?.message || pc.ec);
const lg = await userLogin(user, pass, dev, d);
const ec = lg.j?.data?.error_code ?? lg.ec;
console.log('  user/login http=%s ec=%s', lg.status, ec);
console.log('  resp=', JSON.stringify(lg.j?.data || lg.j).slice(0, 280));
console.log('\n=== KET LUAN GAP#3 ===');
if (ec === 7) console.log('❌ ec7 → device mint VAN untrusted (hoac IP-confound — thu check_email/IP sach).');
else if (ec === 2135 || ec === 2136 || lg.j?.data?.aaas_ticket) console.log('🎉🎉 QUA ec7 → 2135! Device mint TRUSTED. Gap#3: official-app + props sach + rotation → TRUSTED.');
else if (lg.j?.message === 'success' || (lg.j?.data && !ec)) console.log('🎉🎉🎉 LOGIN SUCCESS! Device TRUSTED, account ok.');
else console.log('? ec khac:', ec, '→ xem resp.');
