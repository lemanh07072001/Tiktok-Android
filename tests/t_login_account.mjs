// Test login với user|pass (device fresh)
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin } from '../src/login.mjs';

const USER = 'user5602420442843';
const PASS = '@33dp5YMAiCd';

// Dùng device fixture từ re/
const [DID, IID] = (process.env.RE_DEV || '7654283410013816340|7654515472762717972').split('|');
const dev = { device_id: DID, install_id: IID, id: { openudid: 'o', cdid: 'c', google_aid: 'g' } };

console.log('\n🚀 Login test (user|pass)\n');
console.log('👤 User:', USER);
console.log('🔐 Pass:', PASS);
console.log('📱 Device:', dev.device_id, '\n');

try {
  // [1] Device setup
  console.log('[1] Device setup...');
  const d = await dsign(dev);
  console.log('    dsign s=%s ✓', d.s);
  await warmup(dev, d);
  console.log('    warmup ✓');

  // [2] Pre-check
  console.log('\n[2] Pre-check...');
  const pc = await preCheck(USER, dev, d);
  console.log('    Status:', pc.status, '| Message:', pc.j?.message);
  if (pc.j?.message !== 'success') {
    console.log('    ⚠️  Pre-check not success:', (pc.txt || '').slice(0, 100));
  }

  // [3] Login
  console.log('\n[3] Login attempt...');
  const lg = await userLogin(USER, PASS, dev, d);
  const ec = lg.j?.data?.error_code;

  console.log('    Status:', lg.status);
  console.log('    Result:', lg.j?.message || `ec=${ec}`);

  // [4] Parse result
  console.log('\n' + '='.repeat(60));
  if (lg.j?.message === 'success') {
    console.log('🎉 LOGIN SUCCESS!');
    console.log('   uid:', lg.j?.data?.user_id_str);
    console.log('   sessionid:', (lg.j?.data?.sessionid || '').substring(0, 20) + '...');
  } else if (ec === 2135) {
    console.log('⚠️  2135 suspicious_login (account flagged)');
    console.log('   aaas_ticket:', (lg.j?.data?.aaas_ticket || '').substring(0, 30) + '...');
    console.log('   Action: need aaas verify (email/password) OR use session');
  } else if (ec === 7) {
    console.log('⚠️  ec7 device velocity/untrusted');
    console.log('   Action: need trusted device OR wait');
  } else if (ec === 1105) {
    console.log('⚠️  ec1105 captcha required');
  } else {
    console.log('❌ Login failed');
    console.log('   error_code:', ec);
    console.log('   Response:', JSON.stringify(lg.j, null, 2).slice(0, 300));
  }
  console.log('='.repeat(60));

} catch (err) {
  console.log('\n❌ Error:', err.message);
  console.log(err.stack);
  process.exit(1);
}
