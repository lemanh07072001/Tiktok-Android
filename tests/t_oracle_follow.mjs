// t_oracle_follow.mjs — TEST: genuine X-Argus (phone-oracle) có làm FOLLOW LÊN THẬT không?
//   Login account TRÊN ĐÚNG device phone (identity trích frida) → X-Argus oracle khớp device-state phone.
//   dsign+login+follow đều ký qua METASEC_ORACLE (phone). Sau follow: re-search follow_status để verify THẬT.
//   Chạy: PROXY=.. METASEC_ORACLE=http://127.0.0.1:8790 RE_VER=45.7.3 node re/tests/t_oracle_follow.mjs "user|pass|email|mailpass"
import crypto from 'node:crypto';
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { dsign } from '../src/device.mjs';
import { passportCall, preCheck, storeRegion, getNonce, appRegion, enc, getJar } from '../src/login.mjs';
import { getToken as mtToken, fetchTikTokCode as mtFetch } from '../../mobile/mailtm.mjs';

const PROXY = process.env.PROXY || '';
if (PROXY) setGlobalDispatcher(new ProxyAgent({ uri: PROXY, connect: { timeout: 15000 }, headersTimeout: 30000, bodyTimeout: 30000 }));
const [user, pass, email, mailpass] = (process.argv[2] || '').split('|');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const J = (x) => JSON.stringify(x || '').slice(0, 170);
const storeCk = () => 'store-idc=' + (getJar()['store-idc'] || 'alisg');
const refHdr = { 'x-tt-referer': 'https://inapp.tiktokv.com/ucenter_web/idv_core/verification', 'x-bd-kmsv': '0', 'x-tt-pba-encode': '0000', 'oec-cs-si-a': '2', 'oec-cs-sdk-version': 'v10.02.09-ov-android_V31', 'oec-vc-sdk-version': '3.2.3.i18n', 'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0' };
const authCall = (d2, p) => passportCall(dev, d2, '/passport/aaas/authenticate/', { params: p, extraQuery: { ...p, request_tag_from: 'h5' }, extra: refHdr, cookieOverride: storeCk() });

// ── PHONE device identity (frida DeviceRegisterManager, ce031603, 45.7.3) ──
const dev = {
  device_id: '7674521198550435349', install_id: '7674523412790527764', new_user: 0,
  id: { openudid: '338330350a2a79a2', cdid: '3e233f7c-4f5c-4634-83f8-a4212d13f640',
    clientudid: 'c681c86c-fe12-4462-9bb8-b14c4c106937', google_aid: process.env.GAID || crypto.randomUUID() },
  openudid: '338330350a2a79a2', cdid: '3e233f7c-4f5c-4634-83f8-a4212d13f640',
};

// GENUINE ticket-guard của device phone hiện tại (trích frida ECDSA_sign + token store)
const TG_PRIV = '658db77a259041658cf8237065d76d5f5734a3526bfe54ac6befe3bf6fcf07ca';
const TG_TS_SIGN = 'ts.1.9be819a55a84d2094e1c34620ca98cdd2c1fd429c42133175f08576426c060400e70b4bda82c13836e5cfa18394d70240f8af1631f165ae960122eeffd4533dd';

(async () => {
  console.log('[*] ORACLE =', process.env.METASEC_ORACLE, '| device (phone) =', dev.device_id);
  const d = await dsign(dev, TG_PRIV).catch((e) => ({ _err: e }));   // EC key GENUINE (khớp pubkey đã đăng ký)
  if (d._err) { console.log('[!] dsign lỗi:', d._err.message); return; }
  d.ts_sign = TG_TS_SIGN;   // ts_sign GENUINE (device/key-level) — ép, không để live-capture đè
  console.log('[1] dsign_s=', d.s, '| ép ts_sign GENUINE =', TG_TS_SIGN.slice(0, 20) + '…');

  await storeRegion(dev, d).catch(() => {});
  await getNonce(dev, d).catch(() => {});
  await appRegion(dev, d).catch(() => {});
  const pc = await preCheck(user, dev, d).catch((e) => ({ ec: e.message }));
  console.log('[2] pre_check=', pc.ec);

  const loginParams = { password: enc(pass), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(user) };
  const lg = await passportCall(dev, d, '/passport/user/login/', { params: loginParams });
  console.log('[3] user/login=', lg.ec, '| dc?', !!lg.dc, '|', J(lg.j?.data || lg.j));
  if (String(lg.ec) !== '2135' || !lg.dc) { console.log('❌ user/login KHÔNG 2135 → dừng'); return; }
  const ticket = lg.dc.passport_ticket;
  const extra = Array.isArray(lg.dc.extra) ? lg.dc.extra : [];
  const ch = await passportCall(dev, d, '/passport/aaas/challenges/', { method: 'GET', extraQuery: { request_tag_from: 'h5', skip_handler: 'error_handler', passport_ticket: ticket }, cookieOverride: storeCk() });
  const types = (ch.j?.data?.challenges || []).map((c) => c.type);
  console.log('[4] challenges types=', JSON.stringify(types));

  let authOK = false;
  if (types.includes(3) && !types.includes(2)) {
    const pid = (extra.find((e) => e.type === 3) || extra[0])?.pseudo_id;
    const au = await authCall(d, { mix_mode: '1', password: enc(pass), pseudo_id: pid, challenge_type: '3', action: '5', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '1' });
    console.log('[5-PW] auth=', au.ec, J(au.j?.data || au.j)); authOK = au.j?.message === 'success';
  } else if (types.includes(2)) {
    const pid = (extra.find((e) => e.type === 2) || extra[0])?.pseudo_id;
    const { token } = await mtToken({ address: email, password: mailpass });
    let base = null; try { const b = await mtFetch({ token, lastK: 15 }); base = b?.code; } catch {}
    const asend = await authCall(d, { mix_mode: '0', pseudo_id: pid, challenge_type: '2', action: '3', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '0' });
    console.log('[5a] SEND=', asend.ec); await sleep(8000);
    let vcode = null; const dl = Date.now() + 110000;
    for (let i = 0; Date.now() < dl; i++) { try { const hit = await mtFetch({ token, lastK: 8 }); if (hit?.code && hit.code !== base) { vcode = hit.code; break; } } catch {} await sleep(2500); }
    if (!vcode) { console.log('❌ no code'); return; }
    console.log('[5c] CODE=', vcode);
    const av = await authCall(d, { mix_mode: '1', code: enc(vcode), pseudo_id: pid, challenge_type: '2', action: '4', passport_ticket: ticket, skip_handler: 'error_handler', fixed_mix_mode: '1' });
    console.log('[5-EM] VERIFY=', av.ec, J(av.j?.data || av.j)); authOK = av.j?.message === 'success';
  }
  if (!authOK) { console.log('❌ authenticate chưa qua'); return; }
  console.log('[5] 🎉 AUTHENTICATE QUA');

  const re = await passportCall(dev, d, '/passport/user/login/', { params: loginParams, extra: { 'x-tt-retry-by-x-tt-verify-idv-decision-conf': '1', 'x-tt-passport-ticket': ticket }, cookieOverride: storeCk() });
  const data = re.j?.data || {};
  if (!(re.j?.message === 'success' || data.user_id_str)) { console.log('[6] ❌ re-login', re.ec); return; }
  const sessTok = re.xtt || '';
  console.log('[6] 🎉 SESSION user_id=' + (data.user_id_str || data.user_id) + ' | cookies=' + Object.keys(getJar()).filter((k) => /sess|sid/i.test(k)).join(','));

  // ── FOLLOW qua oracle X-Argus ──
  const AH = 'api22-normal-c-alisg.tiktokv.com';
  const cdid = dev.cdid;
  const target = (process.env.FOLLOW || 'idmahg').replace(/^@/, '');
  const sr = await passportCall(dev, d, '/aweme/v1/discover/search/', { method: 'GET', host: AH, extraQuery: { keyword: target, count: '10', offset: '0', search_source: 'normal_search', type: '1', cdid }, ttToken: sessTok, dropDgClientData: true });
  const hit = (sr.j?.user_list || []).find((u) => (u.user_info?.unique_id || '').toLowerCase() === target.toLowerCase()) || (sr.j?.user_list || [])[0];
  const uid = hit?.user_info?.uid, sec = hit?.user_info?.sec_uid, fs0 = hit?.user_info?.follow_status;
  console.log('[F0] d.ts_sign trước follow = ' + (d.ts_sign || '(RỖNG)').slice(0, 22) + '…');
  console.log('[F1] search sc=' + sr.j?.status_code + ' @' + target + ' uid=' + uid + ' follow_status(before)=' + fs0);
  if (!uid || !sec) { console.log('[F1] ❌ no sec_uid'); return; }
  d.ts_sign = TG_TS_SIGN;   // ép lại (phòng live-capture đè trong search)
  const fp = { user_id: String(uid), sec_user_id: sec, type: '1', channel_id: '0', from: '19', from_pre: '0', previous_page: '', action_time: String(Date.now()), is_network_available: 'true' };
  const fr = await passportCall(dev, d, '/aweme/v1/commit/follow/user/', { method: 'POST', host: AH, params: fp, extraQuery: { cdid }, ttToken: sessTok, keepTgClientData: true, dropDgClientData: true });
  console.log('[F2] follow sc=' + fr.j?.status_code + ' follow_status=' + fr.j?.follow_status + ' | ' + J(fr.j));

  // ── VERIFY THẬT: chờ + re-search follow_status (server có LƯU không) ──
  await sleep(4000);
  const sv = await passportCall(dev, d, '/aweme/v1/discover/search/', { method: 'GET', host: AH, extraQuery: { keyword: target, count: '10', offset: '0', search_source: 'normal_search', type: '1', cdid }, ttToken: sessTok, dropDgClientData: true });
  const hv = (sv.j?.user_list || []).find((u) => (u.user_info?.unique_id || '').toLowerCase() === target.toLowerCase()) || (sv.j?.user_list || [])[0];
  console.log('[F3] VERIFY re-search follow_status(after)=' + hv?.user_info?.follow_status + ' (1=STUCK ✅ / 0=shadow-drop ❌)');
})();
