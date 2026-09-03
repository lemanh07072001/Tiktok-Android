// t_warmup_trust.mjs — TEST giả thuyết C': trust register = REPUTATION HÀNH VI server-side, không attestation.
//   forge register (untrusted/cold) → WARM-UP mức {none|light|heavy} → user/login → đo ec7 vs 2135.
//   heavy = replay cold-boot THẬT (feed-read + passport reads + token/beat, nhịp người) → tích uy tín server-side.
//   Nếu heavy flip ec7→2135 mà none/light ec7 ⇒ C' đúng ⇒ 100% no-phone register KHẢ THI (không phone bước nào).
//   Chạy: PROXY_URL=<residential sạch> WARMUP=heavy node re/tests/t_warmup_trust.mjs "<user>|<pass>"
import './../src/net.mjs';
import crypto from 'node:crypto';
import { registerDevice, dsign, guards } from '../src/device.mjs';
import { signMetasec, metasecBlock, UA } from '../src/sign.mjs';
import { P } from '../src/profile.mjs';
import { passportCall, warmup as lightWarmup, userLogin, preCheck, seedCookies } from '../src/login.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LEVEL = process.env.WARMUP || 'heavy';       // none | light | heavy
const arg = (process.argv[2] || '').split('|');
const USER = (arg[0] || '').trim(), PASS = (arg[1] || '').trim();

// ── 1 feed-read THẬT (aweme) = tín hiệu "browsing người" mạnh nhất cho uy tín ──
async function feedRead(dev, n) {
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const q = new URLSearchParams({
    device_platform: 'android', os: 'android', ssmix: 'a', _rticket: String(nowMs), cdid: dev.id.cdid, channel: 'googleplay',
    aid: '1233', app_name: 'musical_ly', version_code: '2024500030', version_name: '45.0.3', manifest_version_code: '2024500030',
    update_version_code: '2024500030', ab_version: '45.0.3', resolution: P.res, dpi: String(P.dpi), device_type: P.model, device_brand: P.brand,
    language: 'en', os_api: String(P.os_api), os_version: P.osv, ac: 'wifi', region: 'US', sys_region: 'US', app_language: 'en',
    ts: String(nowS), device_id: dev.device_id, iid: dev.install_id, openudid: dev.id.openudid,
    count: '6', feed_style: '0', filter_warn: '0', pull_type: n === 0 ? '0' : '2', type: '0', volume: '0.5',
    aweme_ids: '', preload_aweme_ids: '', req_from: n === 0 ? 'cold_boot' : 'loadmore',
  });
  const url = 'https://api16-normal-c-useast1a.tiktokv.com/aweme/v2/feed/?' + q.toString();
  const blk = ['content-type', 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-req-ticket', String(nowMs), 'user-agent', UA, 'sdk-version', '2'].join('\r\n');
  const sig = await signMetasec(url, blk, nowS);
  const headers = { 'x-ss-req-ticket': String(nowMs), 'user-agent': UA, 'sdk-version': '2', 'accept-encoding': 'gzip', ...sig };
  const resp = await fetch(url, { method: 'GET', headers });
  return resp.status;
}

async function heavyWarmup(dev, d) {
  const log = (...a) => console.log('  [warm]', ...a);
  // pha cold-boot: light (store_region/nonce/region) rồi feed + settings + token/beat, GIÃN NHỊP như người dùng.
  await lightWarmup(dev, d); log('light done');
  for (let round = 0; round < 4; round++) {
    const f = await feedRead(dev, round).catch((e) => 'err:' + e.message); log('feed#' + round, '→', f);
    await sleep(2500 + crypto.randomInt(2500));
    await passportCall(dev, d, '/passport/user/settings/', { method: 'GET' }).then((r) => log('settings', r.status)).catch(() => {});
    await sleep(1500 + crypto.randomInt(2000));
    await passportCall(dev, d, '/passport/token/beat/v2/', { method: 'POST', params: { scene: 'polling', account_sdk_source: 'app' } }).then((r) => log('beat', r.status)).catch(() => {});
    await sleep(3000 + crypto.randomInt(4000));   // nhịp người: ~7-15s/round
  }
}

(async () => {
  console.log('[cfg] WARMUP=' + LEVEL + ' profile=' + P.model + ' proxy=' + (process.env.PROXY_URL ? 'on' : 'DIRECT'));
  const dev = await registerDevice();
  console.log('[1] forge register → device_id=' + dev.device_id + ' new_user=' + dev.new_user);
  seedCookies(dev.cookies);
  const d = await dsign(dev).catch((e) => ({ _err: e }));
  if (d._err) { console.log('[2] dsign FAIL', d._err.message); process.exit(1); }
  console.log('[2] dsign s=' + d.s);
  seedCookies(d.cookies);

  const t0 = Date.now();
  if (LEVEL === 'light') { await lightWarmup(dev, d); console.log('[3] light warmup done'); }
  else if (LEVEL === 'heavy') { console.log('[3] HEAVY warmup (cold-boot replay, nhịp người)...'); await heavyWarmup(dev, d); }
  else console.log('[3] NO warmup (control)');
  console.log('[3] warmup ' + Math.round((Date.now() - t0) / 1000) + 's');

  if (!USER) { console.log('[4] (không có account — dừng ở warmup; pipeline register+warm OK)'); return; }
  const pc = await preCheck(USER, dev, d).catch((e) => ({ _err: e }));
  console.log('[4] pre_check → ec=' + (pc.ec ?? pc._err?.message));
  const lg = await userLogin(USER, PASS, dev, d).catch((e) => ({ _err: e }));
  console.log('[5] user/login → ec=' + (lg.ec ?? lg._err?.message) + ' | ' + String(lg.txt || '').replace(/\s+/g, ' ').slice(0, 100));
  const verdict = lg.ec === 7 ? 'ec7 (UNTRUSTED/throttle)' : (String(lg.ec) === '2135' || lg.ec === 1108 || lg.ec === 0 || lg.j?.message === 'success') ? '🎯 QUA ec7 (TRUSTED — C\' đúng!)' : 'ec=' + lg.ec;
  console.log('[VERDICT] WARMUP=' + LEVEL + ' → ' + verdict);
})();
