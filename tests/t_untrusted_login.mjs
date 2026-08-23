// t_untrusted_login.mjs — nap device untrusted vua forge (untrusted_devreg.json) -> dsign -> login -> ec?
//   Dung DUNG openudid/cdid da dang ky (khong mismatch). x-argus UNIDBG offline (khong oracle/phone).
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin, seedCookies } from '../src/login.mjs';
import fs from 'node:fs';

const combo = process.argv[2] || 'user28122299571120|@K4a@RWnq0RMO';
const [user, pass] = combo.split('|');

const saved = JSON.parse(fs.readFileSync('ground-truth/untrusted_devreg.json', 'utf8'));
const dev = { device_id: saved.device_id, install_id: saved.resp?.install_id_str || saved.resp?.install_id, id: saved.id };
console.log('[untrusted-login] device=%s (fresh forge, new_user=%s)', dev.device_id, saved.new_user);
console.log('  x-argus source = UNIDBG offline (khong phone)');

const d = await dsign(dev);
console.log('  dsign s=%s (trusted neu =1)', d.s);
seedCookies(dev.cookies || {});
try { await warmup(dev, d); } catch (e) { console.log('  warmup:', e.message); }
const pc = await preCheck(user, dev, d);
console.log('  pre_check ec=%s', pc.j?.message || pc.ec);
const lg = await userLogin(user, pass, dev, d);
const ec = lg.j?.data?.error_code ?? lg.ec;
console.log('  user/login http=%s ec=%s', lg.status, ec);
console.log('  resp=', JSON.stringify(lg.j?.data || lg.j).slice(0, 250));
console.log('\n=== KET LUAN ===');
if (ec === 7) console.log('❌ ec7 → device fresh forge UNTRUSTED (dung ky vong). Mau untrusted sach OK.');
else if (ec === 2135 || ec === 2136 || lg.j?.data?.aaas_ticket) console.log('🎉 QUA ec7 → 2135 (device TRUSTED?!) — bat ngo, can dieu tra.');
else console.log('? ec khac:', ec, '(co the IP-block confound hoac account).');
