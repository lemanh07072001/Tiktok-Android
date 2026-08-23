// t_batch_capacity.mjs — ĐO "1 device_id no-phone được mấy account trước ec7".
//   1 forge device (re/src) → loop account (mỗi account 1 proxy IP riêng) → user/login → 2135/ec7.
//   ec7 → rotate device mới (forge, no-phone). Đếm account/device. Giãn nhịp tránh burst.
//   Chạy: node re/tests/t_batch_capacity.mjs   (accounts + proxies hardcode dưới)
import { setGlobalDispatcher, ProxyAgent, Agent } from 'undici';
import { registerDevice, dsign } from '../src/device.mjs';
import { userLogin, preCheck, seedCookies, warmup } from '../src/login.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PACE_MS = parseInt(process.env.PACE_MS || '35000', 10);

const ACCOUNTS = `user3579006141295|1Tikqfa55rg@
user78158129214578|Dy13209gx91@
user9546667652432|Dy1xtumwus0@
user7440579557461|Dy1i67in$v
user4863859274615|1Tik1131tsd@`.trim().split('\n').map((l) => l.split('|'));

const PROXIES = `1.54.6.162:46293:u29f6d53d4d92:p68206ae3cb5f8576ce591534
14.250.78.108:38293:u29f6d53d4d92:p68206ae3cb5f8576ce591534
42.112.131.70:40194:u29f6d53d4d92:p68206ae3cb5f8576ce591534
118.71.117.188:53554:u29f6d53d4d92:p68206ae3cb5f8576ce591534
1.53.84.65:54084:u29f6d53d4d92:p68206ae3cb5f8576ce591534
118.68.93.124:6629:u29f6d53d4d92:p68206ae3cb5f8576ce591534
42.118.16.26:3821:u29f6d53d4d92:p68206ae3cb5f8576ce591534
113.22.22.155:45174:u29f6d53d4d92:p68206ae3cb5f8576ce591534
42.115.15.163:7932:u29f6d53d4d92:p68206ae3cb5f8576ce591534
1.54.56.119:60668:u29f6d53d4d92:p68206ae3cb5f8576ce591534`.trim().split('\n').map((l) => {
  const [ip, port, u, p] = l.split(':');
  return `http://${u}:${p}@${ip}:${port}`;
});

function setProxy(uri) { setGlobalDispatcher(new ProxyAgent({ uri, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 })); }

let device = null, devAcctCount = 0, devIndex = 0;
async function rotateDevice(proxy) {
  setProxy(proxy);
  const dev = await registerDevice();
  const d = await dsign(dev);
  devIndex++; devAcctCount = 0;
  console.log(`\n[DEVICE #${devIndex}] forge no-phone → device_id=${dev.device_id} new_user=${dev.new_user} dsign_s=${d.s}`);
  return { dev, d };
}

(async () => {
  const results = [];
  for (let i = 0; i < ACCOUNTS.length; i++) {
    const [user, pass] = ACCOUNTS[i];
    const proxy = PROXIES[i % PROXIES.length];
    const proxyIp = proxy.split('@')[1];
    if (!device) device = await rotateDevice(proxy);
    setProxy(proxy);
    try {
      await warmup(device.dev, device.d).catch(() => {});   // light warmup (cookie odin_tt)
      const pc = await preCheck(user, device.dev, device.d).catch((e) => ({ _err: e }));
      const lg = await userLogin(user, pass, device.dev, device.d).catch((e) => ({ _err: e }));
      const ec = lg.ec ?? lg._err?.message;
      const ok2135 = String(ec) === '2135' || ec === 1108 || ec === 0 || lg.j?.message === 'success';
      const isEc7 = ec === 7;
      devAcctCount++;
      const tag = ok2135 ? '✅ 2135' : isEc7 ? '❌ ec7' : 'ec=' + ec;
      console.log(`[${i + 1}/10] ${user} | dev#${devIndex}(acct ${devAcctCount}) | IP ${proxyIp} | pre_check=${pc.ec ?? pc._err?.message} | user/login=${tag}`);
      results.push({ user, dev: devIndex, ec, ok: ok2135, ip: proxyIp });
      if (isEc7) { console.log(`   → ec7: ROTATE device_id mới cho account sau`); device = null; }
    } catch (e) { console.log(`[${i + 1}/10] ${user} EXC ${e.message}`); results.push({ user, err: e.message }); }
    if (i < ACCOUNTS.length - 1) await sleep(PACE_MS);
  }
  console.log('\n===== TỔNG KẾT =====');
  const perDev = {};
  for (const r of results) { if (r.dev) (perDev[r.dev] ||= []).push(r.ok ? 'OK' : 'ec7'); }
  for (const [dv, arr] of Object.entries(perDev)) console.log(`device #${dv}: ${arr.filter((x) => x === 'OK').length}/${arr.length} account qua 2135 (${arr.join(',')})`);
  console.log(`Tổng: ${results.filter((r) => r.ok).length}/${results.length} account → 2135 (no-phone); ${devIndex} device_id dùng.`);
})();
