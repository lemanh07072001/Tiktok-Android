// t_trusted.mjs — TEST DỨT ĐIỂM: device_id THẬT của phone (trusted, 7632) + oracle x-argus (mã hóa đúng 7632).
//   Loại nhiễu device-mismatch của test oracle trước (đã dùng forge 7662 ≠ x-argus 7632).
//   METASEC_ORACLE=http://127.0.0.1:8795 BẮT BUỘC (phone app 45.0.3 warm).
//   Nếu 2135 → GỐC ec7 = forge-device untrusted (đúng CLAUDE.md). Nếu ec7 → device-trust bị loại nốt.
import { dsign, newIdentity } from '../src/device.mjs';
import { warmup, preCheck, userLogin, seedCookies } from '../src/login.mjs';

const combo = process.argv[2] || 'user7785224835733|@K4a#XIGjeM0xo';
const [user, pass] = combo.split('|');

console.log('[t_trusted] x-argus source =', process.env.METASEC_ORACLE ? 'ORACLE (genuine phone)' : 'UNIDBG (offline)');

// device trusted: RE_DEV="device_id|install_id" (vd 1 con regbox minted) — mặc định = phone 7632.
//   LƯU Ý: oracle x-argus CHỈ khớp phone 7632; với minted device khác PHẢI dùng UNIDBG (bỏ METASEC_ORACLE).
const [DID, IID] = (process.env.RE_DEV || '7632162877655729682|7654446515603801877').split('|');
const dev = { device_id: DID, install_id: IID, id: newIdentity() };

console.log('[t_trusted] device PHONE THẬT:', dev.device_id, '(oracle x-argus mã hóa đúng device này)');
const d = await dsign(dev);
console.log('[t_trusted] dsign s=%s (trusted nếu =1)', d.s);

seedCookies(dev.cookies || {});
const jarKeys = await warmup(dev, d);
console.log('[t_trusted] warmup cookies:', jarKeys.join(','));

const pc = await preCheck(user, dev, d);
console.log('[t_trusted] pre_check ec=%s login_page=%s', pc.j?.message || pc.ec, pc.j?.data?.login_page_type ?? pc.j?.data?.login_page);

const lg = await userLogin(user, pass, dev, d);
console.log('[t_trusted] user/login http=%s ec=%s', lg.status, lg.j?.data?.error_code ?? lg.ec);
console.log('  resp=', JSON.stringify(lg.j?.data || lg.j).slice(0, 300));

console.log('\n=== KẾT LUẬN ===');
const ec = lg.j?.data?.error_code;
const ok = lg.j?.message === 'success' || (lg.j?.data && !ec);
if (ok) {
  // LOGIN THÀNH CÔNG — bắt session
  const { JAR, cookieHdr } = await import('../src/login.mjs');
  const cookie = cookieHdr();
  const uid = lg.j?.data?.user_id_str || lg.j?.data?.user_id || '';
  const sid = (cookie.match(/sessionid=([0-9a-f]+)/) || [])[1] || '';
  console.log('🎉🎉 LOGIN SUCCESS NO-PHONE! uid=%s sessionid=%s...', uid, sid.slice(0, 12));
  console.log('  x-tt-token:', (lg.xtt || '').slice(0, 40));
  const session = { cookie, deviceId: dev.device_id, iid: dev.install_id, xtt: lg.xtt || '', uid, user, ts: Date.now() };
  const fs = await import('node:fs');
  const out = `re/out/session_${uid || user}.json`;
  fs.mkdirSync('re/out', { recursive: true });
  fs.writeFileSync(out, JSON.stringify(session, null, 2));
  console.log('  💾 saved →', out);

  // VERIFY: authenticated call bằng session vừa lấy (Task 7)
  const { callAuthed } = await import('../src/session.mjs');
  const info = await callAuthed(session, '/passport/account/info/');
  console.log('  ✅ account/info http=%s msg=%s uid=%s', info.status, info.j?.message, info.j?.data?.user_id_str || info.j?.data?.user_id);
} else if (ec === 2135 || ec === 2136 || lg.j?.data?.aaas_ticket) {
  console.log('🎉 QUA ec7 → 2135 verify challenge (device trusted OK; account flagged, cần aaas verify).');
} else if (ec === 7) {
  console.log('❌ VẪN ec7 → device chưa trusted.');
} else {
  console.log('? ec khác:', ec, '→ xem resp.');
}
