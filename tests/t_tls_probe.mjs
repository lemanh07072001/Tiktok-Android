// Test #2 TLS-fingerprint: ký 1 login request, gửi qua 2 client TLS khác nhau (Node undici vs curl) cùng device/account/proxy.
//  Node ec7 + curl 2135 → server tính TLS. Cả 2 ec7 → TLS không phải biến.
import '../src/net.mjs';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dsign } from '../src/device.mjs';
import { buildCall, seedCookies, preCheck } from '../src/login.mjs';

const ATTK = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk';
Object.assign(process.env, { MSB_DEVSTATE_DIR: `${ATTK}/msstate_7665624`, MS_VENDOR: 'libs_trill/', MS_LIBS: 'libs_trill', MS_SIGN_OFF: '0x9ecc0', MS_DISP_OFF: '0x11a1e0', MS_LICENSE_FILE: 'license_mus4573.json', MSB_VER: '45.7.3', MSB_VERCODE: '2024507030', MSB_FULLINIT: '1', MSB_KV: '1', APP_VER: '45.7.3', APP_VC: '2024507030' });

const USER = process.env.RU || 'user8146217183232', PASS = process.env.RP || '@JuVaNIQGOB58';
const dev = { device_id: '7665624514735244821', install_id: '7665628081449109268', id: { openudid: 'c0c0ba3f5d16f614', cdid: '00000000-0000-4000-8000-000000000001', clientudid: '00000000-0000-4000-8000-000000000002', google_aid: 'b13dc71a-a0d0-4509-8450-dae659764fbb' } };
const enc = (s) => Buffer.from(s, 'utf8').map((b) => b ^ 0x05).toString('hex');
const PROXY = process.env.PROXY_URL;
const parseEc = (t) => { try { const j = JSON.parse(t); return j?.data?.error_code ?? j?.message; } catch { return '?'; } };

const d = await dsign(dev); seedCookies(d.cookies || {});
await preCheck(USER, dev, d).catch(() => {});
// build login call (KHÔNG gửi)
const call = await buildCall(dev, d, '/passport/user/login/', { params: { password: enc(PASS), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(USER) } });

// (a) gửi qua Node undici (TLS Node)
let ecNode = '?';
try { const r = await fetch(call.url, { method: 'POST', headers: call.headers, body: call.body }); ecNode = parseEc(await r.text()); } catch (e) { ecNode = 'ERR ' + e.message; }

// (b) gửi qua curl (TLS curl) — cùng proxy, cùng headers/body/url (ký 1 lần, dùng lại trong window)
const hdrArgs = Object.entries(call.headers).flatMap(([k, v]) => ['-H', `${k}: ${v}`]);
const bodyFile = `${ATTK}/_login_body.txt`; fs.writeFileSync(bodyFile, call.body);
let ecCurl = '?';
try {
  const out = execFileSync('curl', ['-s', '--max-time', '25', ...(PROXY ? ['-x', PROXY] : []), '-X', 'POST', ...hdrArgs, '--data-binary', `@${bodyFile}`, call.url], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  ecCurl = parseEc(out);
} catch (e) { ecCurl = 'ERR ' + (e.stderr || e.message || '').slice(0, 80); }

console.log('TLS-probe (cùng device/account/proxy/x-argus, khác client):');
console.log('  Node undici → ec=%s', ecNode);
console.log('  curl        → ec=%s', ecCurl);
console.log(ecNode === ecCurl ? '  ⇒ GIỐNG NHAU → TLS-fingerprint KHÔNG phải biến' : '  ⇒ KHÁC → TLS-fingerprint LÀ biến (server tính client-TLS)');
