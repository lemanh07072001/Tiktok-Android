// t_check_follow.mjs — verify follow CÓ THẬT không (nạp session đã lưu, KHÔNG re-login).
//   1) search target → user_info.follow_status (server có ghi mình follow không: 0=no,1=yes,2=mutual)
//   2) GET target profile qua session → follower_count + relation
//   3) re-issue follow → xem response follow_status/đã-following
//   Chạy: PROXY=.. SESSION_FILE=sess_7247.json TARGET=idmahg node re/tests/t_check_follow.mjs
import fs from 'node:fs';
import crypto from 'node:crypto';
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { passportCall, getJar, seedCookies } from '../src/login.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));
const AH = 'api22-normal-c-alisg.tiktokv.com';
const J = (x) => JSON.stringify(x || '').slice(0, 200);
const target = (process.env.TARGET || 'idmahg').replace(/^@/, '');

const s = JSON.parse(fs.readFileSync(process.env.SESSION_FILE, 'utf8'));
const ECDH = crypto.createECDH('prime256v1'); ECDH.setPrivateKey(Buffer.from(s.device.ecPriv, 'hex'));
const dev = { device_id: s.device.device_id, install_id: s.device.install_id, id: { cdid: s.device.cdid } };
const d = { device_token: s.device.device_token, dtoken_sign: s.device.dtoken_sign, ts_sign: s.device.ts_sign, ECDH, ecPub: Buffer.from(s.device.ecPub, 'hex') };
seedCookies(s.cookies);
const sessTok = s.xtt;
const cdid = s.device.cdid;
console.log('== account', s.user, 'user_id=' + s.user_id, '==');
console.log('session cookies:', Object.keys(getJar()).filter((k) => /sess|sid|odin|uid_tt/i.test(k)).join(','));

(async () => {
  // 1) search target → follow_status theo góc nhìn account này
  const sr = await passportCall(dev, d, '/aweme/v1/discover/search/', { method: 'GET', host: AH, extraQuery: { keyword: target, count: '10', offset: '0', search_source: 'normal_search', type: '1', cdid }, ttToken: sessTok });
  const list = sr.j?.user_list || [];
  const hit = list.find((u) => (u.user_info?.unique_id || '').toLowerCase() === target.toLowerCase()) || list[0];
  const ui = hit?.user_info || {};
  console.log('[1] search status_code=' + sr.j?.status_code + ' | @' + target + ' uid=' + ui.uid + ' follower_count=' + ui.follower_count + ' follow_status=' + ui.follow_status + ' (0=chưa,1=đang follow)');

  // 2) self profile — following_count của chính account
  const selfSec = s.sec_uid || '';
  const prof = await passportCall(dev, d, '/aweme/v1/user/', { method: 'GET', host: AH, extraQuery: { user_id: s.user_id, sec_user_id: selfSec, cdid }, ttToken: sessTok });
  const self = prof.j?.user || {};
  console.log('[2] self status_code=' + prof.j?.status_code + ' | following_count=' + self.following_count + ' follower_count=' + self.follower_count + ' aweme=' + self.aweme_count + (prof.j?.status_code !== 0 ? ' | ' + J(prof.j) : ''));

  // 3) re-issue follow → response
  if (ui.uid && ui.sec_uid) {
    const fp = { user_id: String(ui.uid), sec_user_id: ui.sec_uid, type: '1', channel_id: '0', from: '19', from_pre: '0', previous_page: '', action_time: String(Date.now()), is_network_available: 'true' };
    const fr = await passportCall(dev, d, '/aweme/v1/commit/follow/user/', { method: 'POST', host: AH, params: fp, extraQuery: { cdid }, ttToken: sessTok, keepTgClientData: true });
    console.log('[3] re-follow status_code=' + fr.j?.status_code + ' follow_status=' + fr.j?.follow_status + ' watch_status=' + fr.j?.watch_status + ' | ' + J(fr.j));
  }
})();
