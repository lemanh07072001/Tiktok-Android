// re/src/aaas.mjs — Task 6b: aaas verify EMAIL flow (challenge_type=2, action=3 send / action=4 verify).
//   GROUND-TRUTH (2026-07-11, mitm + JSB-hook): luồng EMAIL aaas PROVEN 200 success (khác luồng PASSWORD action=5 = ec4).
//   Webview JS KHÔNG ký — chỉ gọi native x.request(needCommonParams). Ta thay native = metasec (oracle=genuine).
//   Yêu cầu ground-truth: device_token s:1 (trusted) + x-argus genuine + KHÔNG x-tt-token/sessionid; cookie strip.
//   Test: s=0 (dsign PC) + oracle x-argus → pass hay ec4? Trả lời "cần genuine seal" hay không.
import crypto from 'node:crypto';
import { signMetasec, UA } from './sign.mjs';
import { guards, gunzip } from './device.mjs';
import { passQuery, PHOST, enc, JAR, cookieHdr } from './login.mjs';

// cookie strip cho aaas (ground-truth chỉ giữ mấy cái này, KHÔNG sessionid/csrf)
const STRIP = ['store-idc', 'tt-target-idc', 'odin_tt', 'd_ticket', 'msToken'];
const cookieStripped = () => STRIP.filter(k => JAR[k] != null).map(k => `${k}=${JAR[k]}`).join('; ');

// header idv_core webview-referer (ground-truth authenticate). pba/oec theo 45.0.3 signer.
const REF = {
  'x-tt-referer': 'https://inapp.tiktokv.com/ucenter_web/idv_core/verification',
  'x-bd-kmsv': '0', 'x-tt-pba-encode': '0000',
  'oec-cs-si-a': '2', 'oec-cs-sdk-version': 'v10.02.06-ov-android_V31', 'oec-vc-sdk-version': '3.2.1.i18n',
  'x-vc-bdturing-sdk-version': '2.4.2.i18n', 'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0',
  'rpc-persist-pns-region-1': 'VN|1562822|1581129', 'rpc-persist-pns-region-2': 'VN|1562822|1581129', 'rpc-persist-pns-region-3': 'VN|1562822|1581129',
};

const grab = (resp) => { try { for (const c of (resp.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0]; const i = kv.indexOf('='); if (i > 0) JAR[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); } } catch {} };

// POST authenticate — params vào CẢ query lẫn body (inQuery), cookie strip, referer webview, KHÔNG x-tt-token, sign metasec(oracle).
async function authPost(dev, d, params, { ttToken = '' } = {}) {
  const apiPath = '/passport/aaas/authenticate/';
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const body = new URLSearchParams(Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]))).toString();
  const q = passQuery(dev); q.set('_rticket', String(nowMs)); q.set('ts', String(nowS));
  for (const [k, v] of Object.entries(params)) q.set(k, String(v));   // inQuery
  q.set('request_tag_from', 'h5');
  const url = `https://${PHOST}${apiPath}?` + q.toString();
  const stub = crypto.createHash('md5').update(body).digest('hex').toUpperCase();
  const ck = cookieStripped();
  const g = guards(d, apiPath, nowS, ttToken);   // ticket = x-tt-token (rỗng theo ground-truth)
  const blk = ['x-ss-stub', stub, 'content-type', 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-req-ticket', String(nowMs), 'x-tt-token', ttToken, 'cookie', ck, 'user-agent', UA, 'sdk-version', '2', 'passport-sdk-version', '1'].join('\r\n');
  const sig = await signMetasec(url, blk, nowS);
  const headers = { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-stub': stub, 'x-ss-req-ticket': String(nowMs), 'sdk-version': '2', 'passport-sdk-version': '1', 'accept': 'application/json, text/plain, */*', 'x-tt-dm-status': 'login=0;ct=0;rt=7', 'x-tt-bypass-dp': '1', 'cookie': ck, 'user-agent': UA, 'accept-encoding': 'gzip', ...REF, ...g, ...sig };
  if (ttToken) headers['x-tt-token'] = ttToken;
  const resp = await fetch(url, { method: 'POST', headers, body });
  grab(resp);
  const txt = gunzip(Buffer.from(await resp.arrayBuffer()));
  let j = null; try { j = JSON.parse(txt); } catch {}
  // d_ticket = RESPONSE HEADER (không phải Set-Cookie) — proof-verify cho relogin #7 (note 26).
  return { status: resp.status, txt, j, ec: j?.data?.error_code ?? j?.message, d_ticket: resp.headers.get('d_ticket') || '' };
}

async function aaasGet(dev, d, apiPath, extraQuery = {}, ttToken = '') {
  const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
  const q = passQuery(dev); q.set('_rticket', String(nowMs)); q.set('ts', String(nowS));
  for (const [k, v] of Object.entries(extraQuery)) q.set(k, String(v));
  const url = `https://${PHOST}${apiPath}?` + q.toString();
  const ck = cookieHdr();
  const g = guards(d, apiPath, nowS, ttToken);
  const blk = ['content-type', 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-req-ticket', String(nowMs), 'x-tt-token', ttToken, 'cookie', ck, 'user-agent', UA, 'sdk-version', '2', 'passport-sdk-version', '1'].join('\r\n');
  const sig = await signMetasec(url, blk, nowS);
  const headers = { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-req-ticket': String(nowMs), 'sdk-version': '2', 'passport-sdk-version': '1', 'accept': 'application/json, text/plain, */*', 'cookie': ck, 'user-agent': UA, 'accept-encoding': 'gzip', ...REF, ...g, ...sig };
  if (ttToken) headers['x-tt-token'] = ttToken;
  const resp = await fetch(url, { method: 'GET', headers });
  grab(resp);
  const txt = gunzip(Buffer.from(await resp.arrayBuffer()));
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { status: resp.status, txt, j, ec: j?.data?.error_code ?? j?.message };
}

export const newPseudoId = () => 'PID' + Array.from({ length: 16 }, () => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[crypto.randomInt(36)]).join('');

// challenges → factors ([{type:2}] = email)
export const challenges = (dev, d, ticket, ttToken = '') =>
  aaasGet(dev, d, '/passport/aaas/challenges/', { request_tag_from: 'h5', skip_handler: 'error_handler', passport_ticket: ticket }, ttToken);

// action=3 SEND code tới email
export const authSend = (dev, d, ticket, pid, ttToken = '') =>
  authPost(dev, d, { mix_mode: '0', pseudo_id: pid, challenge_type: '2', action: '3', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '0' }, { ttToken });

// action=4 VERIFY code=enc(code)
export const authVerify = (dev, d, ticket, pid, code, ttToken = '') =>
  authPost(dev, d, { mix_mode: '1', code: enc(code), pseudo_id: pid, challenge_type: '2', action: '4', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '1' }, { ttToken });
