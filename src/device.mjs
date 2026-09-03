// re/src/device.mjs — Task 2 (device_register) + Task 3 (device-guard/ticket-guard).
//   Bám ground-truth: 01_device_register.frida.json (fingerprint) + guards() proven.
//   Note: re/notes/11-device-register.md, 12-device-guard.md.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { signMetasec, UA } from './sign.mjs';
import { P } from './profile.mjs';   // profile device đa dạng (chống velocity-flag)

const gunzip = (b) => { for (const fn of [zlib.gunzipSync, zlib.brotliDecompressSync, zlib.zstdDecompressSync]) { try { return fn(b).toString('utf8'); } catch {} } return b.toString('utf8'); };
const md5U = (s) => crypto.createHash('md5').update(s).digest('hex').toUpperCase();
// grab Set-Cookie → object (odin_tt device cookie set lúc register — mang sang login).
export function grabCookies(resp) { const o = {}; try { for (const c of (resp.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0]; const i = kv.indexOf('='); if (i > 0) o[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); } } catch {} return o; }

// App musically — dùng 45.0.3 khớp signer unidbg (genuine phone 45.7.3; version-pin signer). sig_hash genuine.
export const APP = { aid: 1233, package: 'com.zhiliaoapp.musically', app_name: 'musical_ly', app_version: '45.0.3', version_code: 2024500030, update_version_code: 2024500030, manifest_version_code: 2024500030, sig_hash: '194326e82c84a639a52e5c023116f12a', ab_version: '45.0.3', display_name: 'TikTok' };

// FINGERPRINT.header — ĐA DẠNG theo profile (model/brand/resolution/dpi/os khác nhau mỗi con).
function buildHeader(id) {
  return {
    os: 'Android', os_version: P.osv, os_api: P.os_api, device_model: P.model, device_brand: P.brand, device_manufacturer: P.mfr,
    cpu_abi: 'arm64-v8a', density_dpi: P.dpi, display_density: 'mdpi', resolution: P.res.replace('*', 'x'), display_density_v2: 'xxxhdpi', resolution_v2: P.resv2.replace('*', 'x'),
    access: 'wifi', rom: P.rom, rom_version: P.build, language: 'en', timezone: 7, tz_name: 'Asia/Ho_Chi_Minh', tz_offset: 25200,
    clientudid: id.clientudid, openudid: id.openudid, cdid: id.cdid, google_aid: id.google_aid, req_id: id.req_id,
    device_platform: 'android', channel: 'googleplay', not_request_sender: 1, gaid_limited: 0, guest_mode: 0, is_system_app: 0,
    sdk_flavor: 'i18nInner', sdk_target_version: 30, sdk_version: '2.5.14.5', sdk_version_code: 205140590, git_hash: 'b53ca20', release_build: '348bf6c_20260618',
    custom: { ram_size: '4GB', dark_mode_setting_value: 1, is_flip: false },
    apk_first_install_time: Date.now() - 1000000, tweaked_channel: 'googleplay',
    ...APP, device_id: '0', install_id: '0',
  };
}

export function newIdentity() {
  return { openudid: crypto.randomBytes(8).toString('hex'), cdid: crypto.randomUUID(), clientudid: crypto.randomUUID(), google_aid: crypto.randomUUID(), req_id: crypto.randomUUID() };
}

const commonQ = (id, nowMs, nowS) => new URLSearchParams({ req_id: crypto.randomUUID(), device_platform: 'android', os: 'android', ssmix: 'a', _rticket: String(nowMs), cdid: id.cdid, channel: 'googleplay', aid: '1233', app_name: 'musical_ly', version_code: '2024500030', version_name: '45.0.3', manifest_version_code: '2024500030', update_version_code: '2024500030', ab_version: '45.0.3', resolution: P.res, dpi: String(P.dpi), device_type: P.model, device_brand: P.brand, language: 'en', os_api: String(P.os_api), os_version: P.osv, ac: 'wifi', is_pad: '0', app_type: 'normal', sys_region: 'US', last_install_time: String(nowS - 2), timezone_name: 'Asia/Ho_Chi_Minh', app_language: 'en', timezone_offset: '25200', host_abi: 'arm64-v8a', locale: 'en', ac2: 'wifi', uoo: '1', op_region: 'VN', build_number: '45.0.3', region: 'US', ts: String(nowS), openudid: id.openudid, use_store_region_cookie: '1' });

// ── Task 2: device_register → {device_id, install_id} ──
export async function registerDevice(id = newIdentity(), extraEnv = {}) {
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const body = JSON.stringify({ header: buildHeader(id), magic_tag: 'ss_app_log', _gen_time: nowMs });
  const stub = md5U(body);
  const url = 'https://api-boot.tiktokv.com/service/2/device_register/?' + commonQ(id, nowMs, nowS).toString();
  const blk = ['x-ss-stub', stub, 'content-type', 'application/json; charset=utf-8', 'x-ss-req-ticket', String(nowMs), 'x-tt-dm-status', 'login=0;ct=0;rt=7', 'sdk-version', '2', 'passport-sdk-version', '1', 'user-agent', UA].join('\r\n');
  const sig = await signMetasec(url, blk, nowS, extraEnv);
  const headers = { 'content-type': 'application/json; charset=utf-8', 'x-ss-stub': stub, 'x-ss-req-ticket': String(nowMs), 'x-tt-dm-status': 'login=0;ct=0;rt=7', 'sdk-version': '2', 'passport-sdk-version': '1', 'x-ss-dp': '1233', 'user-agent': UA, 'accept-encoding': 'gzip, deflate, br', ...sig };
  const resp = await fetch(url, { method: 'POST', headers, body });
  const cookies = grabCookies(resp);
  const raw = Buffer.from(await resp.arrayBuffer());
  const j = JSON.parse(gunzip(raw));
  return { device_id: j.device_id_str, install_id: j.install_id_str, new_user: j.new_user, id, cookies, raw: j };
}

// ── Task 3: dsign → device_token (device-guard) + ECDH keypair ──
// device_properties per-device (5 field SHA + random obf keys) — sample-based, dsign không validate forensic.
function genProps() {
  const md5r = () => crypto.randomBytes(16).toString('hex');
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const p = { device_model: P.model, device_manufacturer: P.mfr, resolution: P.res.replace('*', 'x'), disk_size: sha('disk' + md5r()), memory_size: sha('mem' + md5r()), re_time: md5r() };
  for (const k of ['indss18', 'indc15', 'indn5', 'indmc14', 'inda0', 'indal2', 'indm10', 'indsp3', 'indsd8', 'bl', 'cmf', 'bc', 'stz', 'sl']) p[k] = md5r();
  return p;
}
export async function dsign(dev, fixedPrivHex = null) {
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const openudid = dev.id?.openudid || dev.openudid, cdid = dev.id?.cdid || dev.cdid;
  const ECDH = crypto.createECDH('prime256v1'); if (fixedPrivHex) ECDH.setPrivateKey(Buffer.from(fixedPrivHex, 'hex')); else ECDH.generateKeys();
  const ecPub = ECDH.getPublicKey();
  const body = JSON.stringify({ device_id: dev.device_id, install_id: dev.install_id, aid: 1233, app_version: '45.0.3', model: P.model, os: 'Android', openudid, google_aid: dev.id?.google_aid || crypto.randomUUID(), properties_version: 'android-1.0', device_properties: genProps() });
  const stub = md5U(body);
  const q = new URLSearchParams({ from: 'normal', from_error: '', device_platform: 'android', os: 'android', ssmix: 'a', _rticket: String(nowMs), cdid, channel: 'googleplay', aid: '1233', app_name: 'musical_ly', version_code: '2024500030', version_name: '45.0.3', manifest_version_code: '2024500030', update_version_code: '2024500030', ab_version: '45.0.3', resolution: P.res, dpi: String(P.dpi), device_type: P.model, device_brand: P.brand, language: 'en', os_api: String(P.os_api), os_version: P.osv, ac: 'wifi', is_pad: '0', app_type: 'normal', sys_region: 'US', last_install_time: String(nowS - 6), timezone_name: 'Asia/Ho_Chi_Minh', app_language: 'en', timezone_offset: '25200', host_abi: 'arm64-v8a', locale: 'en', ac2: 'wifi', uoo: '0', op_region: 'VN', build_number: '45.0.3', region: 'US', ts: String(nowS), iid: dev.install_id, device_id: dev.device_id, openudid });
  const url = 'https://api.tiktokv.com/service/2/dsign/?' + q.toString();
  const tgPub = ecPub.toString('base64');
  const blk = ['x-ss-stub', stub, 'content-type', 'application/json; charset=utf-8', 'x-ss-req-ticket', String(nowMs), 'tt-ticket-guard-public-key', tgPub, 'tt-device-guard-iteration-version', '1', 'sdk-version', '2', 'passport-sdk-version', '1', 'user-agent', UA].join('\r\n');
  const sig = await signMetasec(url, blk, nowS);
  const headers = { 'content-type': 'application/json; charset=utf-8', 'x-ss-stub': stub, 'x-ss-req-ticket': String(nowMs), 'tt-ticket-guard-public-key': tgPub, 'tt-device-guard-iteration-version': '1', 'sdk-version': '2', 'passport-sdk-version': '1', 'x-ss-dp': '1233', 'user-agent': UA, 'accept-encoding': 'gzip', ...sig };
  const resp = await fetch(url, { method: 'POST', headers, body });
  const cookies = grabCookies(resp);
  const raw = Buffer.from(await resp.arrayBuffer());
  if (resp.status !== 200 || raw.length === 0) { const e = new Error(`dsign http=${resp.status} len=${raw.length}`); e.status = resp.status; throw e; }
  const j = JSON.parse(gunzip(raw));
  const sd = JSON.parse(Buffer.from(j['tt-device-guard-server-data'], 'base64').toString('utf8'));
  const tsSign = sd.ts_sign || (j['tt-ticket-guard-server-data'] ? (JSON.parse(Buffer.from(j['tt-ticket-guard-server-data'], 'base64').toString('utf8')).ts_sign || '') : '');
  let sVal = '?'; try { sVal = JSON.parse(sd.device_token.split('|')[1]).s; } catch {}
  return { device_token: sd.device_token, dtoken_sign: sd.dtoken_sign, ECDH, ecPub, ts_sign: tsSign, s: sVal, cookies };
}

// ── Task 3: device-guard + ticket-guard headers (dreq_sign / req_sign over EC key) ──
const ecKeyOf = (d) => { const p = d.ecPub; return crypto.createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', d: d.ECDH.getPrivateKey().toString('base64url'), x: p.subarray(1, 33).toString('base64url'), y: p.subarray(33, 65).toString('base64url') } }); };
export function guards(d, apiPath, ts, ticket = '', tsSign = d.ts_sign || '') {
  const dgDer = crypto.sign('sha256', Buffer.from(`device_token=${d.device_token}&path=${apiPath}&timestamp=${ts}`, 'latin1'), { key: ecKeyOf(d), dsaEncoding: 'der' });
  const tgDer = crypto.sign('sha256', Buffer.from(`ticket=${ticket}&path=${apiPath}&timestamp=${ts}`, 'latin1'), { key: ecKeyOf(d), dsaEncoding: 'der' });
  return {
    'tt-device-guard-client-data': Buffer.from(JSON.stringify({ device_token: d.device_token, timestamp: ts, req_content: 'device_token,path,timestamp', dtoken_sign: d.dtoken_sign, dreq_sign: dgDer.toString('base64') }), 'utf8').toString('base64'),
    'tt-device-guard-iteration-version': '1',
    'tt-ticket-guard-public-key': d.ecPub.toString('base64'),
    'tt-ticket-guard-version': '3',
    'tt-ticket-guard-iteration-version': '0',
    'tt-ticket-guard-client-data': Buffer.from(JSON.stringify({ req_content: 'ticket,path,timestamp', req_sign: tgDer.toString('base64'), timestamp: ts, ts_sign: tsSign }), 'utf8').toString('base64'),
  };
}
export { md5U, gunzip };
