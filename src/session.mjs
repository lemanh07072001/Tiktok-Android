// re/src/session.mjs — Task 7: XÀI account qua API bằng session sẵn (no-phone, no-password-login).
//   Đường thực chiến khi account đã có session (combo): cookie-only + metasec sign → authenticated call.
//   Bám ground-truth: read passport chấp nhận cookie sessionid (không cần x-tt-token) — verified _api_test.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { metasecBlock, signMetasec, genuineHeaders, UA } from './sign.mjs';

const gunzip = (b) => { for (const fn of [zlib.gunzipSync, zlib.brotliDecompressSync, zlib.zstdDecompressSync]) { try { return fn(b).toString('utf8'); } catch {} } return b.toString('utf8'); };
const PHOST = 'api22-normal-c-alisg.tiktokv.com';   // api22 clean

// commonQuery cho authenticated call (device bất kỳ hợp lệ — read không bind device gốc session).
function commonQuery(deviceId, iid) {
  const nowS = Math.floor(Date.now() / 1000);
  return new URLSearchParams({
    'passport-sdk-version': '1', device_platform: 'android', os: 'android', ssmix: 'a', channel: 'googleplay',
    aid: '1233', app_name: 'musical_ly', version_code: '450003', version_name: '45.0.3', manifest_version_code: '2024500030',
    update_version_code: '2024500030', ab_version: '45.0.3', resolution: '1440*2392', dpi: '560', device_type: 'SM-G930F',
    device_brand: 'samsung', language: 'en', os_api: '28', os_version: '9', ac: 'wifi', is_pad: '0', app_type: 'normal',
    sys_region: 'US', timezone_name: 'Asia/Ho_Chi_Minh', app_language: 'en', timezone_offset: '25200', host_abi: 'arm64-v8a',
    locale: 'en', region: 'US', op_region: 'VN', build_number: '45.0.3', current_region: 'VN', residence: 'VN',
    device_id: deviceId, iid,
  });
}

// Gọi authenticated GET bằng session cookie. cookie = chuỗi "k=v; k=v" từ combo.
export async function callAuthed(session, apiPath, { extraQuery = {}, method = 'GET' } = {}) {
  const { cookie, deviceId = '7661233880557225493', iid = '7661236122685114132', xtt = '' } = session;
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const q = commonQuery(deviceId, iid); q.set('_rticket', String(nowMs)); q.set('ts', String(nowS));
  for (const [k, v] of Object.entries(extraQuery)) q.set(k, String(v));
  const url = `https://${PHOST}${apiPath}?` + q.toString();
  const block = metasecBlock({ stub: null, reqTicket: nowMs, ttToken: xtt, cookie });
  const sig = await signMetasec(url, block, nowS);
  const headers = genuineHeaders({ body: '', reqTicketMs: nowMs, ttToken: xtt, cookie, extra: sig });
  const resp = await fetch(url, { method, headers });
  const txt = gunzip(Buffer.from(await resp.arrayBuffer()));
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { status: resp.status, txt, j };
}

// parse combo (field 7 = cookie) → {cookie, uid}
export function sessionFromCombo(line) {
  const f = line.trim().split('|');
  const cookie = (f[7] || '').trim().replace(/, /g, '; ');
  const uid = (cookie.match(/multi_sids=(\d+)/) || [])[1] || '';
  return { cookie, uid };
}
