// t_full_session.mjs — FULL no-phone SESSION + action (follow) trên re/src.
//   LOGIN: registerDevice+dsign → warmup+pre_check → user/login 2135 → challenges → authenticate
//          (type3=password | type2=email) → re-login #17 → SESSION.  → LƯU session (env SESSION_FILE).
//   REUSE: có SESSION_FILE tồn tại → BỎ QUA login (tránh rate-limit re-verify), nạp session làm action luôn.
//   Action: FOLLOW=<uniqueId> [FOLLOW_TYPE=1|0].
//   Chạy: PROXY=.. SESSION_FILE=sess.json FOLLOW=idmahg FOLLOW_TYPE=0 node re/tests/t_full_session.mjs "user|pass|email|mailpass"
import fs from 'node:fs';
import crypto from 'node:crypto';
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { registerDevice, dsign } from '../src/device.mjs';
import { passportCall, preCheck, storeRegion, getNonce, appRegion, enc, getJar, seedCookies } from '../src/login.mjs';
import { getToken as mtToken, fetchTikTokCode as mtFetch } from '../../mobile/mailtm.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));
const SESS_FILE = process.env.SESSION_FILE || '';
const f = (process.argv[2] || '').split('|');
const [user, pass, email, mailpass] = f;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const J = (x) => JSON.stringify(x || '').slice(0, 170);
const storeCk = () => 'store-idc=' + (getJar()['store-idc'] || 'alisg');
const refHdr = { 'x-tt-referer': 'https://inapp.tiktokv.com/ucenter_web/idv_core/verification', 'x-bd-kmsv': '0', 'x-tt-pba-encode': '0000', 'oec-cs-si-a': '2', 'oec-cs-sdk-version': 'v10.02.06-ov-android_V31', 'oec-vc-sdk-version': '3.2.1.i18n', 'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0' };
const authCall = (dev, d, p) => passportCall(dev, d, '/passport/aaas/authenticate/', { params: p, extraQuery: { ...p, request_tag_from: 'h5' }, extra: refHdr, cookieOverride: storeCk() });

function saveSession(dev, d, sessTok, data) {
  const s = { user, user_id: data.user_id_str || data.user_id, session_key: data.session_key, xtt: sessTok,
    cookies: getJar(),
    device: { device_id: dev.device_id, install_id: dev.install_id, cdid: dev.id?.cdid || '',
      device_token: d.device_token, dtoken_sign: d.dtoken_sign, ts_sign: d.ts_sign || '',
      ecPub: d.ecPub.toString('hex'), ecPriv: d.ECDH.getPrivateKey().toString('hex') } };
  fs.writeFileSync(SESS_FILE, JSON.stringify(s, null, 2));
  console.log('[6+] session ĐÃ LƯU →', SESS_FILE);
}
function loadSession() {
  const s = JSON.parse(fs.readFileSync(SESS_FILE, 'utf8'));
  const ECDH = crypto.createECDH('prime256v1'); ECDH.setPrivateKey(Buffer.from(s.device.ecPriv, 'hex'));
  const dev = { device_id: s.device.device_id, install_id: s.device.install_id, id: { cdid: s.device.cdid } };
  const d = { device_token: s.device.device_token, dtoken_sign: s.device.dtoken_sign, ts_sign: s.device.ts_sign, ECDH, ecPub: Buffer.from(s.device.ecPub, 'hex') };
  seedCookies(s.cookies);
  console.log('[S] NẠP session', SESS_FILE, '| user_id=', s.user_id, '| cookies=', Object.keys(s.cookies).length);
  return { dev, d, sessTok: s.xtt };
}

async function login() {
  if (!user || !pass) { console.error('cần "user|pass|email|mailpass" để login'); process.exit(1); }
  const dev = await registerDevice();
  const d = await dsign(dev);
  console.log('[1] device', dev.device_id, 'dsign_s=', d.s, 'new_user=', dev.new_user);
  await storeRegion(dev, d).catch(() => {});
  await getNonce(dev, d).catch(() => {});
  await appRegion(dev, d).catch(() => {});
  const pc = await preCheck(user, dev, d).catch((e) => ({ ec: e.message }));
  console.log('[2] warmup+pre_check → pre_check=', pc.ec);

  const loginParams = { password: enc(pass), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(user) };
  const lg = await passportCall(dev, d, '/passport/user/login/', { params: loginParams });
  console.log('[3] user/login=', lg.ec, '| dc?', !!lg.dc, '|', J(lg.j?.data || lg.j));
  if (String(lg.ec) !== '2135' || !lg.dc) { console.log('❌ user/login KHÔNG ra 2135 (ec=' + lg.ec + ') → dừng'); return null; }
  const ticket = lg.dc.passport_ticket;
  const extra = Array.isArray(lg.dc.extra) ? lg.dc.extra : [];
  console.log('[3*] 2135 ticket=' + ticket + ' extra=' + J(extra.map((e) => ({ t: e.type, pid: e.pseudo_id }))));

  const ch = await passportCall(dev, d, '/passport/aaas/challenges/', { method: 'GET', extraQuery: { request_tag_from: 'h5', skip_handler: 'error_handler', passport_ticket: ticket }, cookieOverride: storeCk() });
  const challenges = ch.j?.data?.challenges || [];
  console.log('[4] challenges=', ch.ec, '| factors=', J(challenges));
  const types = challenges.map((c) => c.type);

  let authOK = false;
  if (types.includes(3) && !types.includes(2)) {
    const pid = (extra.find((e) => e.type === 3) || extra[0])?.pseudo_id;
    const au = await authCall(dev, d, { mix_mode: '1', password: enc(pass), pseudo_id: pid, challenge_type: '3', action: '5', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '1' });
    console.log('[5-PW] authenticate PASSWORD=', au.ec, '|', J(au.j?.data || au.j));
    authOK = au.j?.message === 'success';
  } else if (types.includes(2)) {
    const pid = (extra.find((e) => e.type === 2) || extra[0])?.pseudo_id;
    if (!email || !mailpass) { console.log('❌ challenge EMAIL nhưng thiếu email/mailpass'); return null; }
    const { token } = await mtToken({ address: email, password: mailpass });
    let base = null; try { const b = await mtFetch({ token, lastK: 15 }); base = b?.code; } catch {}
    const asend = await authCall(dev, d, { mix_mode: '0', pseudo_id: pid, challenge_type: '2', action: '3', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '0' });
    console.log('[5a] authenticate SEND=', asend.ec, '|', J(asend.j?.data || asend.j));
    console.log('[5b] chờ mã verify email…'); await sleep(8000);
    let vcode = null; const dl = Date.now() + 110000;
    for (let i = 0; Date.now() < dl; i++) {
      try { const hit = await mtFetch({ token, lastK: 8 }); if (hit?.code && hit.code !== base) { vcode = hit.code; break; } } catch {}
      if (i % 6 === 0) process.stdout.write('.'); await sleep(2500);
    }
    console.log();
    if (!vcode) { console.log('❌ no verify code'); return null; }
    console.log('[5c] VERIFY CODE=', vcode);
    const av = await authCall(dev, d, { mix_mode: '1', code: enc(vcode), pseudo_id: pid, challenge_type: '2', action: '4', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '1' });
    console.log('[5-EM] authenticate VERIFY=', av.ec, '|', J(av.j?.data || av.j));
    authOK = av.j?.message === 'success';
  } else { console.log('⚠️ challenge type=' + JSON.stringify(types) + ' chưa hỗ trợ'); return null; }
  if (!authOK) { console.log('❌ authenticate chưa qua'); return null; }
  console.log('[5] 🎉 AUTHENTICATE QUA');

  const re = await passportCall(dev, d, '/passport/user/login/', { params: loginParams, extra: { 'x-tt-retry-by-x-tt-verify-idv-decision-conf': '1', 'x-tt-passport-ticket': ticket }, cookieOverride: storeCk() });
  console.log('[6] re-login=', re.ec, '|', J(re.j?.data || re.j));
  const data = re.j?.data || {};
  if (!(re.j?.message === 'success' || data.session_key || data.user_id_str || data.user_id)) { console.log('[6] ❌ re-login chưa ra session (ec=' + re.ec + ')'); return null; }
  console.log('[6] 🎉🎉🎉 SESSION! user_id=' + (data.user_id_str || data.user_id) + ' session_key=' + String(data.session_key || '').slice(0, 24) + '…');
  const sessTok = re.xtt || '';
  if (SESS_FILE) saveSession(dev, d, sessTok, data);
  return { dev, d, sessTok };
}

async function followAction(dev, d, sessTok) {
  const AH = 'api22-normal-c-alisg.tiktokv.com';   // aweme host (khác passport api16)
  const jk = getJar();
  console.log('[F0] session cookies:', Object.keys(jk).filter((k) => /sess|sid|tt_token|odin|uid_tt|multi|guard/i.test(k)).join(',') || '(none)', '| xtt=', sessTok ? sessTok.slice(0, 16) + '…' : '(none)');
  const cdid = dev.id?.cdid || '';
  const target = process.env.FOLLOW.replace(/^@/, '');
  const sr = await passportCall(dev, d, '/aweme/v1/discover/search/', { method: 'GET', host: AH, extraQuery: { keyword: target, count: '10', offset: '0', search_source: 'normal_search', type: '1', cdid }, ttToken: sessTok });
  const list = sr.j?.user_list || [];
  const hit = list.find((u) => (u.user_info?.unique_id || '').toLowerCase() === target.toLowerCase()) || list[0];
  const uid = hit?.user_info?.uid, sec = hit?.user_info?.sec_uid;
  console.log('[F1] search @' + target + ' → status_code=' + sr.j?.status_code + ' users=' + list.length + ' | uid=' + uid + ' sec=' + (sec || '').slice(0, 18) + '…');
  if (!uid || !sec) { console.log('[F1] ❌ không resolve được sec_uid |', J(sr.j)); return; }
  const ftype = process.env.FOLLOW_TYPE || '1';   // 1=follow, 0=unfollow
  const fp = { user_id: String(uid), sec_user_id: sec, type: ftype, channel_id: '0', from: '19', from_pre: '0', previous_page: '', action_time: String(Date.now()), is_network_available: 'true' };
  const fr = await passportCall(dev, d, '/aweme/v1/commit/follow/user/', { method: 'POST', host: AH, params: fp, extraQuery: { cdid }, ttToken: sessTok, keepTgClientData: true });
  console.log('[F2] ' + (ftype === '0' ? 'UNfollow' : 'follow') + ' → http=' + fr.status + ' status_code=' + fr.j?.status_code + ' follow_status=' + fr.j?.follow_status + ' | ' + J(fr.j));
  if (fr.j?.status_code === 0) console.log('[F2] 🎉🎉 ' + (ftype === '0' ? 'UNFOLLOW' : 'FOLLOW') + ' OK — follow_status=' + fr.j?.follow_status);
}

(async () => {
  let sess;
  if (SESS_FILE && fs.existsSync(SESS_FILE)) sess = loadSession();   // reuse: KHỎI re-login
  else sess = await login();
  if (!sess) return;
  if (process.env.FOLLOW) await followAction(sess.dev, sess.d, sess.sessTok);
})();
