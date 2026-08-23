// Test Re-Register: Tạo device_id mới bằng fingerprint mới
// Goal: Xem TikTok có tạo device_id mới không, hay trả cũ
import '../src/net.mjs';
import { registerDevice, newIdentity } from '../src/device.mjs';
import fs from 'node:fs';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function testReRegister() {
  console.log('\n🔍 TEST RE-REGISTER: Tạo device_id mới\n');
  console.log('Kịch bản: Tạo 3 fingerprint khác nhau → Server tạo device_id mới?');
  console.log('='.repeat(70));

  const devices = [];

  for (let i = 1; i <= 3; i++) {
    console.log(`\n[${i}] Register device ${i}...`);

    try {
      // Tạo fingerprint HOÀN TOÀN MỚI
      const id = newIdentity();
      console.log(`    openudid: ${id.openudid.substring(0, 16)}...`);
      console.log(`    cdid: ${id.cdid.substring(0, 16)}...`);

      // Call device_register
      const dev = await registerDevice(id);

      console.log(`    ✅ device_id: ${dev.device_id}`);
      console.log(`    install_id: ${dev.install_id}`);
      console.log(`    new_user: ${dev.new_user}`);

      devices.push({
        order: i,
        device_id: dev.device_id,
        install_id: dev.install_id,
        new_user: dev.new_user,
        openudid: id.openudid,
        cdid: id.cdid,
      });

      if (i < 3) {
        console.log(`\n    ⏱️  Waiting 6s before next register...`);
        await sleep(6000);
      }
    } catch (err) {
      console.log(`    ❌ Error: ${err.message}`);
      console.log(`    Status: ${err.status}`);
      console.log(`    Response: ${err.response?.slice?.(0, 200) || 'N/A'}`);
    }
  }

  // Analyze results
  console.log('\n' + '='.repeat(70));
  console.log('\n📊 ANALYSIS:\n');

  const uniqueIds = new Set(devices.map(d => d.device_id));
  const uniqueInstallIds = new Set(devices.map(d => d.install_id));

  console.log(`Total devices registered: ${devices.length}`);
  console.log(`Unique device_ids: ${uniqueIds.size}`);
  console.log(`Unique install_ids: ${uniqueInstallIds.size}`);

  if (uniqueIds.size === devices.length) {
    console.log('\n✅ KẾT QUẢ: Mỗi fingerprint MỚI → device_id MỚI (Server tạo)');
    console.log('   Re-register ĐƯỢC ✅');
  } else if (uniqueIds.size === 1) {
    console.log('\n❌ KẾT QUẢ: Tất cả cùng device_id (Server lấy từ cache)');
    console.log('   Nguyên nhân: Có thể fingerprint bị detect giống nhau?');
    console.log('   Re-register KHÔNG được ❌');
  } else {
    console.log(`\n⚠️  KẾT QUẢ: Hỗn hợp (${uniqueIds.size} device_ids từ ${devices.length} attempts)`);
    console.log('   Cần investigate thêm');
  }

  // Detail log
  console.log('\n📝 DETAIL LOG:\n');
  devices.forEach((d, idx) => {
    console.log(`${idx + 1}. device_id=${d.device_id} | install_id=${d.install_id} | new_user=${d.new_user}`);
  });

  // Save results
  fs.mkdirSync('re/out', { recursive: true });
  fs.writeFileSync('re/out/reregister_test.json', JSON.stringify(devices, null, 2));
  console.log('\n💾 Kết quả lưu: re/out/reregister_test.json');

  return {
    success: uniqueIds.size === devices.length,
    uniqueCount: uniqueIds.size,
    totalAttempts: devices.length,
    devices,
  };
}

testReRegister().catch(console.error);
