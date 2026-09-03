// re/src/login.mjs — Task 5: login chain pre_check → user/login → 2135 (KHÔNG ec7).
//   Điểm mấu chốt vs pure-API cũ: dùng genuineHeaders() (đủ oec-cs/oec-vc/rpc-persist/pba/request-tag) + guards().
//   Bám ground-truth: 02_auth_chain.mitm.json (genuine user/login → 2135).
import crypto from 'node:crypto';
import { genuineHeaders, metasecBlock, signMetasec, UA } from './sign.mjs';
import { guards, gunzip } from './device.mjs';
import { P } from './profile.mjs';

export const PHOST = 'api16-normal-c-alisg.tiktokv.com';
// enc = XOR 0x05 → hex (username/password/code/email). dec = nghịch đảo. VERIFY byte-exact vs genuine (notes/16).
export const enc = (s) => Buffer.from(s, 'utf8').map((b) => b ^ 0x05).toString('hex');
export const dec = (h) => Buffer.from(Buffer.from(h, 'hex').map((b) => b ^ 0x05)).toString('utf8');

// commonQuery passport — bám genuine query user/login. version_code=450003 (45.0.3 khớp signer; genuine 45.7.3=450703).
// Đã thêm field genuine trước thiếu: current_region, last_install_time, residence, ac2, uoo, support_webview.
// RE_VER: '45.7.3' (default, spoof khớp genuine) | '45.0.3' (khớp signer). Test biến version.
const V = process.env.RE_VER === '45.0.3'
  ? { name: '45.0.3', code: '450003', mvc: '2024500030' }
  : { name: '45.7.3', code: '450703', mvc: '2024507030' };
export function passQuery(dev) {
  const nowS = Math.floor(Date.now() / 1000);
  return new URLSearchParams({
    'passport-sdk-version': '1', device_platform: 'android', os: 'android', ssmix: 'a', channel: 'googleplay',
    aid: '1233', app_name: 'musical_ly', version_code: V.code, version_name: V.name, manifest_version_code: V.mvc,
    update_version_code: V.mvc, ab_version: V.name, resolution: P.res, dpi: String(P.dpi), device_type: P.model,
    device_brand: P.brand, language: 'en', os_api: String(P.os_api), os_version: P.osv, ac: 'wifi', is_pad: '0', app_type: 'normal',
    sys_region: 'US', timezone_name: 'Asia/Ho_Chi_Minh', app_language: 'en', timezone_offset: '25200', host_abi: 'arm64-v8a',
    locale: 'en', region: 'US', op_region: 'VN', build_number: V.name,
    current_region: 'VN', residence: 'VN', ac2: 'wifi', uoo: '0', support_webview: '1', last_install_time: String(nowS - 200),
    cronet_version: '41c3dc2f_2026-04-08', ttnet_version: '4.2.243.50-tiktok', use_store_region_cookie: '1',
    device_id: dev.device_id, iid: dev.install_id,
  });
}

// Cookie trước login. Genuine có store-idc/tt-target-idc + **msToken** (client-gen msSDK). msToken có thể là gốc ec7.
let JAR = { 'store-idc': 'alisg', 'tt-target-idc': 'alisg' };
if (process.env.RE_MSTOKEN) JAR.msToken = process.env.RE_MSTOKEN;
const cookieHdr = () => Object.entries(JAR).map(([k, v]) => `${k}=${v}`).join('; ');
const grab = (resp) => { try { for (const c of (resp.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0]; const i = kv.indexOf('='); if (i > 0) JAR[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); } } catch {} };
// seed cookie từ register/dsign (odin_tt device cookie) vào jar login.
export function seedCookies(obj) { Object.assign(JAR, obj || {}); }
export const getJar = () => ({ ...JAR });

// build-only: dựng {url, method, headers, body} KHÔNG gửi — dùng cho diff vs genuine.
export async function buildCall(dev, d, apiPath, { method = 'POST', params = {}, extraQuery = {}, ttToken = '', extra = {}, cookieOverride = null, host = PHOST, keepTgClientData = false, dropDgClientData = false } = {}) {
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const body = method === 'POST' ? new URLSearchParams(Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]))).toString() : '';
  const q = passQuery(dev); q.set('_rticket', String(nowMs)); q.set('ts', String(nowS));
  for (const [k, v] of Object.entries(extraQuery)) q.set(k, String(v));
  const url = `https://${host}${apiPath}?` + q.toString();
  const cookie = cookieOverride != null ? cookieOverride : cookieHdr();
  const stub = body ? crypto.createHash('md5').update(body).digest('hex').toUpperCase() : null;
  const block = metasecBlock({ stub, reqTicket: nowMs, ttToken, cookie });
  const sig = await signMetasec(url, block, nowS);
  const g = guards(d, apiPath, nowS, ttToken);
  if (!keepTgClientData) delete g['tt-ticket-guard-client-data'];   // genuine user/login KHÔNG gửi; write-op (follow/digg) thì CẦN → keepTgClientData
  if (dropDgClientData) { delete g['tt-device-guard-client-data']; delete g['tt-device-guard-iteration-version']; }   // genuine aweme write-op KHÔNG gửi device-guard
  const headers = genuineHeaders({ body, reqTicketMs: nowMs, ttToken, cookie, extra: { ...g, ...sig, ...extra } });
  return { url, method, headers, body };
}

// 1 passport call — FULL genuine headers + guards + metasec. body='' cho GET.
export async function passportCall(dev, d, apiPath, opts = {}) {
  const { url, method, headers, body } = await buildCall(dev, d, apiPath, opts);
  const resp = await fetch(url, { method, headers, body: method === 'POST' ? body : undefined });
  grab(resp);
  // ⭐ LIVE ts_sign: server cấp tt-ticket-guard-server-data (per-session) → cập nhật d.ts_sign cho ticket-guard write-op (follow).
  try { const sd = resp.headers.get('tt-ticket-guard-server-data') || resp.headers.get('Tt-Ticket-Guard-Server-Data'); if (sd) { const dec = Buffer.from(sd, 'base64').toString('utf8'); if (process.env.TS_DEBUG) console.log('[ts-server-data @' + apiPath + '] RAW=' + sd + '\n   DECODED=' + dec); const ts = JSON.parse(dec).ts_sign; if (ts) d.ts_sign = ts; } } catch {}
  const raw = Buffer.from(await resp.arrayBuffer());
  const txt = gunzip(raw);
  let j = null; try { j = JSON.parse(txt); } catch {}
  // 2135: ticket + pseudo_id nằm ở HEADER x-tt-verify-idv-decision-conf (note 19), KHÔNG ở body
  let dc = null; try { const h = resp.headers.get('x-tt-verify-idv-decision-conf'); if (h) dc = JSON.parse(h); } catch {}
  return { status: resp.status, txt, j, ec: j?.data?.error_code ?? j?.message, xtt: resp.headers.get('x-tt-token') || '', dc };
}

// ── warmup pre-login (genuine làm trước user/login → lập cookie odin_tt + device session) ──
export const storeRegion = (dev, d) => passportCall(dev, d, '/passport/app/store_region/', { params: { store_region_src: 'uid' } });
export const getNonce = (dev, d) => passportCall(dev, d, '/passport/auth/get_nonce/', { params: { platform: 'google' } });
export const appRegion = (dev, d) => passportCall(dev, d, '/passport/app/region/', { params: { type: '2', hashed_id: crypto.createHash('sha256').update(dev.device_id).digest('hex') } });
export async function warmup(dev, d) {
  await storeRegion(dev, d).catch(() => {});
  await getNonce(dev, d).catch(() => {});
  await appRegion(dev, d).catch(() => {});
  return Object.keys(JAR);
}

// pre_check → login_page
export async function preCheck(username, dev, d) {
  return passportCall(dev, d, '/passport/user/login/pre_check/', { params: { account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(username) } });
}
// user/login → 2135 (+aaas_ticket) hoặc ec7
export async function userLogin(username, password, dev, d) {
  return passportCall(dev, d, '/passport/user/login/', { params: { password: enc(password), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(username) } });
}
export { cookieHdr, JAR };
