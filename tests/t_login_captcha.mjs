// t_login_captcha.mjs — LOGIN 1108 (verify_center whirl) → giải captcha THẬT trong Chrome (SDK oracle) → re-login → session.
//   MERGE từ mobile/captcha_chrome_solve.mjs (Chrome-oracle ký /captcha/*) sang re/ + feed device-state + login flow.
//   Chạy: PROXY_URL=.. MSB_DEVSTATE_DIR=.. DID/IID/OPENUDID=.. node re/tests/t_login_captcha.mjs "user|pass"
import '../src/net.mjs';
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { signOffline } from '../../mobile/sign.mjs';
import { dsign } from '../src/device.mjs';
import { userLogin, seedCookies, enc, JAR, cookieHdr } from '../src/login.mjs';
import { UA } from '../src/sign.mjs';

const CHROME = fs.existsSync('C:/Program Files/Google/Chrome/Application/chrome.exe')
  ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
  : path.join(process.env.HOME || process.env.USERPROFILE, 'AppData/Local/ms-playwright/chromium-1217/chrome-win64/chrome.exe');
const VHOST = 'rc-verification-sg.tiktokv.com';
const [USER, PASS] = (process.argv[2] || 'user9390461650709|@bDAx6B1rj6ik8').split('|');
const dev = {
  device_id: process.env.DID || '7665645055429248532', install_id: process.env.IID || '7665647638889858837',
  id: { openudid: process.env.OPENUDID || '5b41298a86a7be93', cdid: '11111111-0000-4000-8000-000000000001', clientudid: '22222222-0000-4000-8000-000000000002', google_aid: '00000000-0000-4000-8000-000000000000' },
};
const OUT = path.join(process.env.TEMP || '.', 'captcha_login'); fs.mkdirSync(OUT, { recursive: true });

console.log('[*] login', USER, '| device', dev.device_id, '| feed=', !!process.env.MSB_DEVSTATE_DIR);
const d = await dsign(dev); console.log('[1] dsign', d.device_token ? '✅' : '❌'); if (!d.device_token) process.exit(1);
seedCookies(d.cookies || {});
// bare login → 1108 + verify_center_decision_conf
const lg = await userLogin(USER, PASS, dev, d);
const ec = lg.j?.data?.error_code;
const vd = lg.j?.data?.verify_center_decision_conf;
console.log('[2] user/login ec=' + ec + (vd ? ' | verify_center ✅' : ''));
if (ec === 0 || lg.j?.message === 'success') { console.log('🎉 login SUCCESS thẳng (không captcha)'); process.exit(0); }
if (!vd) { console.log('→ ec=' + ec + ' không có verify_center (ec7=account bị đốt? / feed thiếu?). resp:', JSON.stringify(lg.j?.data).slice(0, 150)); process.exit(1); }

// Chrome proxy
let chromeProxy;
if (process.env.PROXY_URL) { const u = new URL(process.env.PROXY_URL); chromeProxy = { server: u.protocol + '//' + u.host, username: decodeURIComponent(u.username) || undefined, password: decodeURIComponent(u.password) || undefined }; }
const browser = await chromium.launch({ executablePath: CHROME, headless: false, args: ['--disable-blink-features=AutomationControlled'], proxy: chromeProxy });
const ctx = await browser.newContext({ userAgent: UA });
const page = await ctx.newPage();

// ký metasec mọi /captcha/*
await page.route(/rc-verification.*\/captcha\/(get|verify|report)/, async (route) => {
  const req = route.request(); const url = req.url(); const m = req.method();
  const body = m === 'POST' ? (req.postData() || '') : null;
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const stub = body ? crypto.createHash('md5').update(body).digest('hex').toUpperCase() : null;
  const blk = [stub ? 'x-ss-stub' : null, stub, 'content-type', 'application/json; charset=utf-8', 'x-ss-req-ticket', String(nowMs), 'x-tt-token', '', 'cookie', 'store-idc=alisg', 'user-agent', UA, 'sdk-version', '2', 'passport-sdk-version', '1'].filter((x) => x !== null).join('\r\n');
  let sig = {}; try { sig = signOffline(url, blk, nowS); } catch (e) { console.log('   sign err:', e.message); }
  const headers = { ...req.headers(), 'content-type': 'application/json; charset=utf-8', 'x-tt-token': '', 'cookie': 'store-idc=alisg', 'user-agent': UA, 'sdk-version': '2', 'passport-sdk-version': '1', ...sig };
  if (stub) { headers['x-ss-stub'] = stub; headers['x-ss-req-ticket'] = String(nowMs); }
  console.log('   [ký]', m, '/captcha/' + url.split('/captcha/')[1].split('?')[0]);
  await route.continue({ headers });
});
await ctx.route('bytedance://**', (r) => r.abort().catch(() => {}));
let resolveDone; const doneP = new Promise((r) => { resolveDone = r; });
page.on('response', async (resp) => {
  const u = resp.url();
  if (/\/captcha\/verify(\?|$)/.test(u)) {
    try { const t = await resp.text(); if (/success|"code":\s*200|complete/i.test(t)) { console.log('   [VERIFY] PASS'); resolveDone(true); } } catch {}
  }
});

// verifycenter URL — subtype WHIRL (1108) thay vì slide
const params = new URLSearchParams({ verify_host: 'https://' + VHOST + '/', aid: '1233', lang: 'en', app_name: 'musical_ly', locale: 'en', ch: 'googleplay', channel: 'googleplay', app_key: '', iid: dev.install_id, vc: '45.7.3', app_version: '45.7.3', did: dev.device_id, device_id: dev.device_id, session_id: '', region: 'sg', userMode: '257', use_native_report: '0', use_jsb_request: '0', orientation: '2', challenge_code: '99999', subtype: 'whirl', verify_data: vd, h5_sdk_version: '2.34.12', sdk_version: '2.4.2.i18n', os_type: '0', theme: 'light' });
const vcUrl = 'https://www.tiktok.com/verifycenter/ttcaptcha/?' + params.toString();
console.log('\n[3] 🖱️  MỞ Chrome — GIẢI CAPTCHA WHIRL (xoay ảnh) bằng tay. SDK tự submit.\n');
await page.goto(vcUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch((e) => console.log('   goto:', e.message));
const r = await Promise.race([doneP, new Promise((res) => setTimeout(() => res('timeout'), 240000))]);
console.log('\n[4]', r === true ? '🎉 CAPTCHA PASS' : '⏱️ ' + r);
await browser.close();
if (r !== true) { console.log('→ captcha chưa qua, chạy lại.'); process.exit(0); }

// re-login sau captcha PASS → session
const lg2 = await userLogin(USER, PASS, dev, d);
const ec2 = lg2.j?.data?.error_code ?? lg2.j?.message;
console.log('[5] re-login ec=' + ec2);
if (lg2.j?.message === 'success' || lg2.j?.data?.user_id_str) {
  const uid = lg2.j?.data?.user_id_str;
  const sess = { user: USER, device: dev.device_id, iid: dev.install_id, cookie: cookieHdr(), xtt: lg2.xtt || '', uid, ts: Date.now() };
  fs.mkdirSync('re/out', { recursive: true });
  fs.writeFileSync(`re/out/session_login_${uid || USER}.json`, JSON.stringify(sess, null, 2));
  console.log('🎉🎉 LOGIN SESSION HOÀN CHỈNH — uid=' + uid + ' → re/out/session_login_' + (uid || USER) + '.json');
} else console.log('→ re-login ec=' + ec2 + ' (2135=cần email-verify / 1108=captcha lại). resp:', JSON.stringify(lg2.j?.data).slice(0, 120));
