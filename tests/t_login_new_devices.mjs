// Test login với 3 device_id mới từ re-register
// Goal: Xem device mới có login được không (ec7? 2135? success?)
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin } from '../src/login.mjs';
import fs from 'node:fs';

const USER = 'user5602420442843';
const PASS = '@33dp5YMAiCd';

async function testLoginOnDevice(deviceId, installId, label) {
  console.log(`\n${label}`);
  console.log('─'.repeat(60));
  console.log(`Device: ${deviceId}`);
  console.log(`Install ID: ${installId}`);

  try {
    const dev = { device_id: deviceId, install_id: installId, id: {} };

    // [1] Device setup
    console.log('[1] Device setup...');
    const d = await dsign(dev);
    console.log(`    dsign s=${d.s}`);
    await warmup(dev, d);
    console.log('    warmup ✓');

    // [2] Pre-check
    console.log('[2] Pre-check...');
    const pc = await preCheck(USER, dev, d);
    console.log(`    Status: ${pc.status}`);
    console.log(`    Message: ${pc.j?.message}`);

    if (pc.j?.message !== 'success') {
      console.log(`    ⚠️  Pre-check failed: ${pc.j?.data?.description?.slice(0, 60) || 'unknown'}`);
      return { device_id: deviceId, result: 'pre_check_failed', ec: pc.j?.data?.error_code };
    }

    // [3] Login
    console.log('[3] Login...');
    const lg = await userLogin(USER, PASS, dev, d);
    const ec = lg.j?.data?.error_code;
    const msg = lg.j?.message;

    console.log(`    Status: ${lg.status}`);
    console.log(`    Result: ${msg || `ec=${ec}`}`);

    // [4] Analyze
    if (msg === 'success') {
      console.log('    🎉 LOGIN SUCCESS!');
      console.log(`    uid: ${lg.j?.data?.user_id_str}`);
      return { device_id: deviceId, result: 'success', uid: lg.j?.data?.user_id_str };
    } else if (ec === 2135) {
      console.log('    ⚠️  2135 suspicious_login (account flagged)');
      return { device_id: deviceId, result: '2135', aaas_ticket: !!lg.j?.data?.aaas_ticket };
    } else if (ec === 7) {
      console.log('    ⚠️  ec7 device untrusted (thiết bị mới, expected)');
      return { device_id: deviceId, result: 'ec7' };
    } else if (ec === 1105) {
      console.log('    ⚠️  ec1105 captcha required');
      return { device_id: deviceId, result: 'ec1105' };
    } else {
      console.log(`    ❌ Login failed: ec=${ec}`);
      return { device_id: deviceId, result: `ec${ec}`, error: lg.j?.data?.description };
    }
  } catch (err) {
    console.log(`    ❌ Error: ${err.message}`);
    return { device_id: deviceId, result: 'error', error: err.message };
  }
}

async function main() {
  console.log('\n🚀 TEST LOGIN trên 3 device mới (từ re-register)\n');
  console.log('='.repeat(70));

  // Đọc kết quả từ re-register test
  let devices = [];
  try {
    const data = JSON.parse(fs.readFileSync('re/out/reregister_test.json', 'utf8'));
    devices = data;
    console.log(`\nLoaded ${devices.length} devices từ re-register test\n`);
  } catch (err) {
    console.log(`\n⚠️  Không tìm thấy reregister_test.json`);
    console.log(`    Run: node re/tests/t_reregister_device.mjs trước\n`);
    process.exit(1);
  }

  // Test login trên mỗi device
  const results = [];
  for (let i = 0; i < devices.length; i++) {
    const dev = devices[i];
    const label = `[Device ${i + 1}/${devices.length}]`;
    const result = await testLoginOnDevice(dev.device_id, dev.install_id, label);
    results.push(result);

    if (i < devices.length - 1) {
      console.log('\n⏱️  Waiting 5s...');
      await new Promise(r => setTimeout(r, 5000));
    }
  }

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('\n📊 SUMMARY:\n');

  const summary = {
    total: results.length,
    success: results.filter(r => r.result === 'success').length,
    '2135': results.filter(r => r.result === '2135').length,
    'ec7': results.filter(r => r.result === 'ec7').length,
    'ec1105': results.filter(r => r.result === 'ec1105').length,
    'failed': results.filter(r => r.result.startsWith('ec') || r.result === 'error').length,
  };

  console.log(`Total tested: ${summary.total}`);
  console.log(`✅ SUCCESS: ${summary.success}`);
  console.log(`⚠️  2135 (account flagged): ${summary['2135']}`);
  console.log(`⚠️  ec7 (device untrusted): ${summary.ec7}`);
  console.log(`⚠️  ec1105 (captcha): ${summary.ec1105}`);
  console.log(`❌ Other errors: ${summary.failed}`);

  // Detail
  console.log('\n📝 DETAIL:\n');
  results.forEach((r, i) => {
    const status = r.result === 'success' ? '✅' : r.result === '2135' ? '⚠️' : r.result === 'ec7' ? '⚠️' : '❌';
    console.log(`${status} Device ${i + 1}: ${r.result}`);
  });

  // Save results
  fs.writeFileSync('re/out/login_new_devices_result.json', JSON.stringify({
    timestamp: new Date().toISOString(),
    user: USER,
    summary,
    results,
  }, null, 2));
  console.log('\n💾 Kết quả lưu: re/out/login_new_devices_result.json');

  // Conclusion
  console.log('\n' + '='.repeat(70));
  console.log('\n💡 KẾT LUẬN:\n');

  if (summary.success > 0) {
    console.log('✅ Device mới CÓ THỂ login thành công!');
    console.log('   → Re-register để tạo device mới là CÁCH TỐTCHUẨN');
  } else if (summary['2135'] > 0) {
    console.log('⚠️  Device mới login được (pass pre_check) nhưng account bị flag 2135');
    console.log('   → Cần aaas verify hoặc email-code login');
  } else if (summary.ec7 > 0) {
    console.log('⚠️  Device mới bị ec7 (thiết bị không tin cậy)');
    console.log('   → Thiết bị cần "aged" (~24h) mới được login');
    console.log('   → Hoặc dùng device cũ/đã tin cậy từ pool');
  } else {
    console.log('❌ Device mới KHÔNG thể login hiện tại');
    console.log('   Lý do: ' + (results[0]?.error || 'unknown'));
  }
}

main().catch(console.error);
