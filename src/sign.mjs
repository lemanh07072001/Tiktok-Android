// re/src/sign.mjs — Signing layer (Task 1). Bám ground-truth: re/notes/10-signing.md.
//   3 lớp: (1) metasec 4-header (x-argus/gorgon/ladon/khronos) — wrap unidbg;
//          (2) device-guard, (3) ticket-guard — Task 3 (src/device.mjs).
//   Điểm mới vs pure-API cũ: dựng ĐỦ header client-genuine (oec-cs/oec-vc/rpc-persist/pba/request-tag đầy đủ).
//
//   CLEAN-ROOM: chỉ 1 cầu nối được phép — metasec .so qua unidbg (spec sanction "dùng lại unidbg, WRAP").
//   Server-deploy: cần JDK21+unidbg (như regbox vendored) HOẶC metasec_node pure-node (sau).
import crypto from 'node:crypto';
import http from 'node:http';
import { signOffline } from '../../mobile/sign.mjs';   // BRIDGE metasec (version-pinned infra, không phải RE logic)
// oracle localhost qua node:http (KHÔNG undici) → không dính global proxy dispatcher + tránh undici-instance mismatch.
function oracleSign(oracleBase, url, block) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ url, hdr: block });
    const u = new URL(oracleBase.replace(/\/$/, '') + '/sign');
    const req = http.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
      (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } }); });
    req.on('error', reject); req.setTimeout(20000, () => req.destroy(new Error('oracle timeout'))); req.write(body); req.end();
  });
}

// ── hằng số client-genuine (ground-truth 45.7.3) ──
import { makeUA } from './profile.mjs';
// UA version = env RE_VER. UA model đa dạng theo profile (chống velocity-flag fingerprint đồng nhất).
export const APP_VC = process.env.RE_VER === '45.7.3' ? '2024507030' : '2024500030';
export const UA = makeUA(APP_VC);
// oec/vc/pns theo genuine. rpc-persist-pns-region = VN|<geoname>|<sub> từ capture.
// Giá trị 45.0.3 (khớp genuine phone 45.0.3, byte-verified diff). 45.7.3 dùng oec v10.02.09/3.2.3, pba 0020.
const V45 = process.env.RE_VER === '45.7.3';
const CLIENT_GENUINE = {
  'oec-cs-sdk-version': V45 ? 'v10.02.09-ov-android_V31' : 'v10.02.06-ov-android_V31',
  'oec-cs-si-a': '2',
  'oec-vc-sdk-version': V45 ? '3.2.3.i18n' : '3.2.1.i18n',
  'rpc-persist-pns-region-1': 'VN|1562822|1581129',
  'rpc-persist-pns-region-2': 'VN|1562822|1581129',
  'rpc-persist-pns-region-3': 'VN|1562822|1581129',
  'x-vc-bdturing-sdk-version': '2.4.2.i18n',
  'x-bd-kmsv': '0',
  'x-tt-bypass-dp': '1',
  'x-tt-pba-encode': V45 ? '0020' : '4000',
  'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0',
  'passport-sdk-settings': 'x-tt-token',
  'passport-sdk-sign': 'x-tt-token',
  'passport-sdk-version': '1',
  'sdk-version': '2',
};

export const md5stub = (body) => body ? crypto.createHash('md5').update(body).digest('hex').toUpperCase() : null;

// Header BLOCK (\r\n key\r\n value) làm INPUT cho metasec — đúng thứ tự signer kỳ vọng.
export function metasecBlock({ stub, reqTicket, ttToken = '', cookie, ua = UA }) {
  const parts = [];
  if (stub) parts.push('x-ss-stub', stub);
  parts.push('content-type', 'application/x-www-form-urlencoded; charset=UTF-8');
  parts.push('x-ss-req-ticket', String(reqTicket));
  parts.push('x-tt-token', ttToken);
  parts.push('cookie', cookie);
  parts.push('user-agent', ua);
  parts.push('sdk-version', '2', 'passport-sdk-version', '1');
  return parts.join('\r\n');
}

// Ký metasec 4-header. Trả {X-Gorgon, X-Khronos, X-Ladon, X-Argus}. Time-bound (khronos=giây).
//   METASEC_ORACLE=http://127.0.0.1:8795 → ký GENUINE bằng app phone (x-argus 688, app-grade) thay unidbg (324).
export async function signMetasec(url, block, khronosSec = Math.floor(Date.now() / 1000), extraEnv = {}) {
  const oracle = process.env.METASEC_ORACLE;
  if (oracle) {
    const j = await oracleSign(oracle, url, block);
    if (j && j['X-Argus']) return j;
    throw new Error('oracle sign fail: ' + JSON.stringify(j).slice(0, 100));
  }
  return signOffline(url, block, khronosSec, extraEnv);
}

const traceId = () => '00-' + crypto.randomBytes(16).toString('hex') + '-' + crypto.randomBytes(8).toString('hex') + '-01';

// Dựng FULL header genuine cho 1 passport request. Bám genuine user/login (không 'accept', x-tt-token bỏ nếu rỗng).
export function genuineHeaders({ body = '', reqTicketMs, ttToken = '', cookie, extra = {}, dg = {}, tg = {} }) {
  const stub = md5stub(body);
  const h = {
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'x-ss-req-ticket': String(reqTicketMs),
    'cookie': cookie,
    'user-agent': UA,
    'accept-encoding': 'gzip, deflate, br',
    'x-tt-trace-id': traceId(),
    ...CLIENT_GENUINE,
    ...dg, ...tg, ...extra,
  };
  if (ttToken) h['x-tt-token'] = ttToken;   // genuine BỎ x-tt-token khi rỗng (pre-login)
  if (stub) h['x-ss-stub'] = stub;
  return h;
}

export { CLIENT_GENUINE };
