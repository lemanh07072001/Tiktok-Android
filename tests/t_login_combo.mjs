// Login user|pass (BỎ cookie) trên device_id MỚI trusted (Widevine-rotated 7665624), ký offline, proxy sạch.
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, preCheck, warmup, seedCookies } from '../src/login.mjs';

const USER = process.env.RU || 'user8146217183232';
const PASS = process.env.RP || '@JuVaNIQGOB58';
const dev = {
  device_id: process.env.DID || '7665624514735244821',
  install_id: process.env.IID || '7665628081449109268',
  id: { openudid: process.env.OPENUDID || 'c0c0ba3f5d16f614', cdid: '77777777-0000-4000-8000-000000000001',
        clientudid: '88888888-0000-4000-8000-000000000002', google_aid: process.env.GAID || 'b13dc71a-a0d0-4509-8450-dae659764fbb' },
};
console.log('device=%s oracle=%s', dev.device_id, process.env.METASEC_ORACLE ? 'ON' : 'off');
const v = (ec) => ec === 7 ? '❌ec7(untrusted/velocity)' : ec === 2135 ? '✅2135(trusted→verify)' : (ec === 0 || ec === 1091 || ec === 'success') ? '✅SUCCESS(trusted)' : 'other:' + ec;

const d = await dsign(dev); console.log('dsign s=%s token=%s', d.s, !!d.device_token);
if (!d.device_token) process.exit(1);
seedCookies(d.cookies || {});   // chỉ odin_tt từ dsign, KHÔNG cookie account
await warmup(dev, d).catch(() => {});
const pc = await preCheck(USER, dev, d);
console.log('pre_check ec=%s data=%s', pc.ec, JSON.stringify(pc.j?.data || '').slice(0, 100));
const r = await userLogin(USER, PASS, dev, d);
console.log('user/login ec=%s msg=%s desc=%s', r.j?.data?.error_code ?? r.j?.message, r.j?.message, (r.j?.data?.description || '').slice(0, 70));
const uid = r.j?.data?.user_id_str;
console.log('=> device %s : %s%s', dev.device_id, v(r.j?.data?.error_code ?? r.j?.message), uid ? ' uid=' + uid : '');
if (r.j?.message === 'success') console.log('   🎉 LOGIN SUCCESS no-phone bằng user|pass trên device_id MỚI');
