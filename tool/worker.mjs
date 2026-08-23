// re/tool/worker.mjs — chạy login chain cho 1 account (1 cửa sổ CMD), in ✓/✗ từng bước,
//   thành công thì FETCH + in INFO chi tiết (follower/following/video/likes...). Bám note 26.
//   Account: env ACCOUNT hoặc argv[2] = "user|pass|email|mailpass[|did|iid|openudid|cdid|gaid]".
//   Proxy:   env PROXY_URL (mỗi cửa sổ 1 IP). Signer: env METASEC_ORACLE (genuine) | mặc định unidbg offline.
import '../src/net.mjs';            // side-effect: proxy egress từ PROXY_URL
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { registerDevice, dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin, passportCall, seedCookies, getJar, cookieHdr, enc, JAR } from '../src/login.mjs';
import { challenges, authSend, authVerify, newPseudoId } from '../src/aaas.mjs';
import { callAuthed } from '../src/session.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, 'out');
const DEV = path.join(HERE, 'devices');                       // mỗi account 1 device_id BỀN
const safeName = (s) => String(s).replace(/[^\w.-]/g, '_').slice(0, 60);

// ── error model: StepError chỉ đúng HÀM hỏng khi TikTok update ──
const HINTS = {
  '*7': 'ec7 = velocity/rate-limit theo device_id + IP-register (note 26). KHÔNG phải X-Argus/recipe. '
      + 'Mint device trên IP residential SẠCH + login CÙNG IP; throttle đã trip = chờ giờ.',
  '*1105': 'ec1105 = captcha — device forge/untrusted hoặc IP bẩn. Cần trusted device (dsign s=1) + IP sạch.',
  '*2135': 'ec2135 = account bị-cờ (ở user_login = đúng kỳ vọng → đi tiếp aaas).',
  'sign': 'signer hỏng — METASEC_ORACLE (genuine) chết, hoặc unidbg offline chưa compile/JDK21. '
        + 'Nhớ: login account CŨ thường cần X-Argus GENUINE (phone-oracle), offline chỉ đủ format.',
  'register_device': 'device_register không trả device_id — schema đổi hoặc bị chặn (IP/fingerprint).',
  'dsign': 'dsign http≠200 — device bị ban hoặc device-guard đổi.',
  'challenges': 'không có factor type=2 (email) — luồng verify đổi, hoặc ticket/pseudo_id sai.',
  'relogin': 'relogin #7 fail — header x-tt-passport-ticket + d_ticket + cookie strip 5-key (note 26).',
};
const hintFor = (step, ec) => HINTS['*' + ec] || HINTS[step] || null;

class StepError extends Error {
  constructor(step, layer, o = {}) {
    super(`[${layer}] ${step}: ec=${o.ec} http=${o.http}`);
    Object.assign(this, { step, layer, ...o });
    this.hint = o.hint || hintFor(step, o.ec);
  }
  report() {
    const L = [`\n✗ ${this.step}  [${this.layer}]`];
    if (this.endpoint) L.push(`    endpoint ${this.endpoint}`);
    const m = [];
    if (this.http != null) m.push(`http=${this.http}`);
    if (this.ec != null) m.push(`ec=${this.ec}`);
    if (m.length) L.push('    ' + m.join('  '));
    if (this.msg) L.push(`    msg: ${this.msg}`);
    if (this.hint) L.push(`    hint: ${this.hint}`);
    if (this.raw != null) L.push('    raw: ' + (typeof this.raw === 'string' ? this.raw : JSON.stringify(this.raw)).slice(0, 600));
    return L.join('\n');
  }
}

const ok = (s, d = '') => console.log(`✓ ${s}` + (d ? `   ${d}` : ''));

// gọi 1 step, throw StepError (attribute đúng hàm) nếu lỗi hạ tầng (network/sign)
async function run(step, fn) {
  try { return await fn(); }
  catch (e) {
    if (e instanceof StepError) throw e;
    const msg = e.message || String(e);
    let ohost = ''; try { ohost = process.env.METASEC_ORACLE ? new URL(process.env.METASEC_ORACLE).host : ''; } catch {}
    // signer: lỗi nhắc argus/gorgon/oracle-sign, unidbg/java/mvn (offline), hoặc trúng host oracle
    const isSigner = /argus|gorgon|khronos|ladon|oracle sign|unidbg|\bjava\b|\bmvn\b|jdk|Harness/i.test(msg) || (ohost && msg.includes(ohost));
    if (isSigner) throw new StepError(step, 'SIGN', { msg, hint: HINTS.sign });
    throw new StepError(step, 'NET', { msg, hint: 'Lỗi mạng — check PROXY_URL còn sống + signer (METASEC_ORACLE/unidbg) còn chạy + host reachable.' });
  }
}

// business ec: success → 'success'; ec ∈ allow → ec; còn lại throw StepError
function checkEc(r, step, layer, endpoint, allow = []) {
  if (r.j?.message === 'success') return 'success';
  const ec = r.j?.data?.error_code ?? r.j?.message;
  if (allow.includes(ec)) return ec;
  throw new StepError(step, layer, { endpoint, http: r.status, ec, msg: r.j?.data?.description || r.j?.message, raw: r.j });
}

// strip cookie 5-key cho relogin (note 26)
const strip5 = () => { const J = getJar(); return ['store-idc', 'tt-target-idc', 'odin_tt', 'd_ticket', 'msToken'].filter(k => J[k] != null).map(k => `${k}=${J[k]}`).join('; '); };

// ── đọc mã email: RE_CODE > mail.tm > stdin ──
async function mailtmRead(address, password, timeoutMs = 120000) {
  const tok = await (await fetch('https://api.mail.tm/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address, password }) })).json();
  if (!tok.token) throw new Error('mail.tm auth fail');
  const H = { authorization: 'Bearer ' + tok.token };
  const seen = new Set(); const deadline = Date.now() + timeoutMs;
  const grab = (t) => (t && (t.match(/\b(\d{6})\b/) || t.match(/\b(\d{4,5})\b/)) || [])[1] || null;
  while (Date.now() < deadline) {
    const lst = (await (await fetch('https://api.mail.tm/messages', { headers: H })).json())['hydra:member'] || [];
    for (const m of lst) {
      if (seen.has(m.id)) continue; seen.add(m.id);
      let c = grab(m.subject);
      if (!c) { try { const full = await (await fetch('https://api.mail.tm/messages/' + m.id, { headers: H })).json(); c = grab(full.text) || grab(full.subject); } catch {} }
      if (c) return c;
    }
    await new Promise(r => setTimeout(r, 4000));
  }
  return null;
}
function promptStdin(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(q, a => { rl.close(); res((a || '').trim()); }));
}
async function readCode(acc) {
  if (process.env.RE_CODE) return process.env.RE_CODE;
  if (acc.email && acc.mailpass) { try { const c = await mailtmRead(acc.email, acc.mailpass); if (c) return c; } catch {} }
  return promptStdin(`Nhập mã verify gửi tới ${acc.email || '(email)'}: `);
}

function parseAccount(line) {
  const f = String(line).split('|').map(s => s.trim());
  return { username: f[0], password: f[1], email: f[2] || '', mailpass: f[3] || '', did: f[4] || '', iid: f[5] || '', openudid: f[6] || '', cdid: f[7] || '', gaid: f[8] || '' };
}

// ── in INFO chi tiết + lưu ──
async function showInfo(uid, session) {
  const prof = await callAuthed(session, '/aweme/v1/user/profile/self/', { extraQuery: { user_id: uid } }).catch(e => ({ status: 'ERR', j: null, err: e.message }));
  const u = prof.j?.data?.user || prof.j?.user || {};
  let acc = {};
  try { const ai = await callAuthed(session, '/passport/account/info/v2/', { extraQuery: { scene: 'normal' } }); acc = ai.j?.data || {}; } catch {}
  const info = {
    ok: !!(u.uid || u.nickname), uid, nickname: u.nickname ?? null, unique_id: u.unique_id ?? null,
    signature: u.signature ?? null, region: u.region ?? null,
    follower_count: u.follower_count ?? null, following_count: u.following_count ?? null,
    aweme_count: u.aweme_count ?? null, total_favorited: u.total_favorited ?? null,
    favoriting_count: u.favoriting_count ?? null, create_time: u.create_time ?? null,
    email: acc.email ?? null, mobile: acc.mobile ?? null, has_password: acc.has_password ?? null,
  };
  console.log('\n════════════ THÔNG TIN TÀI KHOẢN ════════════');
  console.log(`  uid          : ${uid}`);
  console.log(`  nickname     : ${info.nickname}`);
  console.log(`  unique_id (@): ${info.unique_id}`);
  console.log(`  follower     : ${info.follower_count}   (người theo dõi)`);
  console.log(`  following    : ${info.following_count}   (đang theo dõi)`);
  console.log(`  video        : ${info.aweme_count}`);
  console.log(`  ❤ nhận (like): ${info.total_favorited}   (total_favorited)`);
  console.log(`  ❤ đã thả     : ${info.favoriting_count}   (favoriting_count)`);
  console.log(`  region       : ${info.region}`);
  console.log(`  email        : ${info.email}`);
  console.log(`  has_password : ${info.has_password}`);
  console.log('══════════════════════════════════════════════');
  try { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(path.join(OUT, `${uid}.json`), JSON.stringify({ ...info, cookie: session.cookie, ts: Date.now() }, null, 2)); console.log(`  (đã lưu ${path.join('out', uid + '.json')})`); } catch {}
  return info;
}

async function main() {
  const line = process.env.ACCOUNT || process.argv[2];
  if (!line || line.split('|').length < 2) { console.error('cần ACCOUNT="user|pass|email|mailpass"'); process.exit(2); }
  const acc = parseAccount(line);
  const u = acc.username, pw = acc.password;
  console.log('── re/tool login chain ──');
  console.log(`   account=${u}  signer=${process.env.METASEC_ORACLE || 'unidbg-offline'}  proxy=${process.env.PROXY_URL ? 'ON' : 'off'}`);

  try {
    // 02 device: MỖI ACCOUNT 1 device_id RIÊNG + BỀN (lưu re/tool/devices/<user>.json).
    //    ưu tiên: device provided ở account.txt > device đã lưu (tái dùng) > register mới rồi LƯU.
    let dev;
    const devFile = path.join(DEV, safeName(u) + '.json');
    if (acc.did && acc.iid) {
      dev = { device_id: acc.did, install_id: acc.iid, id: { openudid: acc.openudid, cdid: acc.cdid, google_aid: acc.gaid || crypto.randomUUID() }, cookies: {} };
      ok('02 device (provided)', `did=${dev.device_id} iid=${dev.install_id}`);
    } else if (fs.existsSync(devFile)) {
      dev = JSON.parse(fs.readFileSync(devFile, 'utf8')); dev.cookies = {};
      ok('02 device (reuse)', `did=${dev.device_id} iid=${dev.install_id} (đã lưu → giữ device riêng)`);
    } else {
      dev = await run('register_device', () => registerDevice());
      if (!dev.device_id) throw new StepError('register_device', 'DEVICE', { endpoint: '/service/2/device_register/', raw: dev.raw });
      try { fs.mkdirSync(DEV, { recursive: true }); fs.writeFileSync(devFile, JSON.stringify({ device_id: dev.device_id, install_id: dev.install_id, new_user: dev.new_user, id: dev.id, profile: process.env.RE_PROFILE ?? null, ts: Date.now() }, null, 2)); } catch {}
      ok('02 register_device (mới)', `did=${dev.device_id} iid=${dev.install_id} new_user=${dev.new_user} → đã lưu devices/${safeName(u)}.json`);
    }

    // 03 dsign + guards
    const d = await run('dsign', () => dsign(dev));
    ok('03 dsign+guards', `s=${d.s} ts_sign=${d.ts_sign ? 'yes' : 'no'}`);

    // 04 seed cookie odin_tt
    seedCookies(dev.cookies); seedCookies(d.cookies);
    ok('04 seed_cookies', `jar=${Object.keys(getJar())}`);

    // 05 warmup (best-effort)
    await run('warmup', () => warmup(dev, d)).catch(() => {});
    ok('05 warmup', `jar=${Object.keys(getJar())}`);

    // 06 pre_check (best-effort)
    try { const pc = await preCheck(u, dev, d); ok('06 pre_check', `status=${pc.status} ec=${pc.j?.data?.error_code} msg=${pc.j?.message}`); }
    catch (e) { console.log('  (06 pre_check bỏ qua) ' + e.message); }

    // 07 user_login → success | 2135 | ec7
    const lg = await run('user_login', () => userLogin(u, pw, dev, d));
    const res = checkEc(lg, 'user_login', 'LOGIN', '/passport/user/login/', [2135]);
    if (res === 'success') {
      ok('07 user_login', 'ĐĂNG NHẬP THẲNG (account chưa bị cờ)');
      const uid = lg.j?.data?.user_id_str || String(lg.j?.data?.user_id || '');
      ok('DONE', `uid=${uid} session_key=${(lg.j?.data?.session_key || '').slice(0, 12)}…`);
      await showInfo(uid, { cookie: cookieHdr(), deviceId: dev.device_id, iid: dev.install_id, xtt: lg.xtt || '' });
      return finish();
    }
    // 2135 branch
    const dc = lg.dc || {};
    const ticket = dc.passport_ticket;
    const pid = (dc.extra?.[0]?.pseudo_id) || newPseudoId();
    if (!ticket) throw new StepError('user_login', 'LOGIN', { endpoint: '/passport/user/login/', http: lg.status, ec: 2135, raw: dc, hint: '2135 nhưng thiếu passport_ticket ở header x-tt-verify-idv-decision-conf.' });
    ok('07 user_login', `2135 (bị cờ, đúng kỳ vọng) ticket=${ticket.slice(0, 10)}… pid=${pid.slice(0, 10)}…`);

    // 08 challenges → factor type=2
    const ch = await run('challenges', () => challenges(dev, d, ticket));
    checkEc(ch, 'challenges', 'AAAS', '/passport/aaas/challenges/', [0, undefined]);
    const factors = ch.j?.data?.challenges || ch.j?.challenges || [];
    const types = factors.map(c => c.type);
    if (!types.includes(2)) throw new StepError('challenges', 'AAAS', { endpoint: '/passport/aaas/challenges/', http: ch.status, raw: ch.j, hint: `không có factor type=2 (email). types=${JSON.stringify(types)}.` });
    ok('08 challenges', `factors=${JSON.stringify(types)} (2=email)`);

    // 09 auth_send action=3
    const se = await run('auth_send', () => authSend(dev, d, ticket, pid));
    checkEc(se, 'auth_send', 'AAAS', '/passport/aaas/authenticate/');
    ok('09 auth_send', 'server đã gửi mã tới email');

    // 10 đọc mã email
    const code = await readCode(acc);
    if (!code) throw new StepError('read_code', 'EMAIL', { hint: 'Không lấy được mã (timeout/không tới). Set RE_CODE hoặc nhập tay.' });
    ok('10 read_code', `code=${code}`);

    // 11 auth_verify action=4 → d_ticket
    const vf = await run('auth_verify', () => authVerify(dev, d, ticket, pid, code));
    checkEc(vf, 'auth_verify', 'AAAS', '/passport/aaas/authenticate/');
    ok('11 auth_verify', `verified d_ticket=${vf.d_ticket ? 'yes' : 'NO(!)'}`);

    // 12 relogin #7 → session
    if (vf.d_ticket) JAR['d_ticket'] = vf.d_ticket;
    const rl = await run('relogin', () => passportCall(dev, d, '/passport/user/login/', {
      params: { password: enc(pw), account_sdk_source: 'app', multi_login: '1', mix_mode: '1', username: enc(u) },
      extra: { 'x-tt-retry-by-x-tt-verify-idv-decision-conf': '1', 'x-tt-passport-ticket': ticket },
      cookieOverride: strip5(),
    }));
    checkEc(rl, 'relogin', 'LOGIN', '/passport/user/login/');
    const uid = rl.j?.data?.user_id_str || String(rl.j?.data?.user_id || '');
    ok('12 relogin', `uid=${uid} session_key=${(rl.j?.data?.session_key || '').slice(0, 12)}…`);
    console.log(`✓ DONE  session_key=${rl.j?.data?.session_key}  user_id=${uid}`);
    await showInfo(uid, { cookie: cookieHdr(), deviceId: dev.device_id, iid: dev.install_id, xtt: rl.xtt || lg.xtt || '' });
    return finish();

  } catch (e) {
    if (e instanceof StepError) { console.log(e.report()); appendFail(u, e); }
    else { console.log(`\n✗ LỖI KHÔNG XÁC ĐỊNH: ${e.stack || e.message}`); appendFail(u, { step: 'unknown', ec: '', report: () => e.message }); }
    return finish(1);
  }
}

function appendFail(user, e) {
  try { fs.mkdirSync(OUT, { recursive: true }); fs.appendFileSync(path.join(OUT, 'fail.txt'), `${user}\t${e.step}\tec=${e.ec ?? ''}\n`); } catch {}
}
function finish(code = 0) {
  // giữ cửa sổ mở để đọc kết quả (trừ khi NO_PAUSE)
  if (process.env.NO_PAUSE) return process.exit(code);
  return promptStdin('\n[Enter để đóng cửa sổ] ').then(() => process.exit(code));
}

main();
