#!/usr/bin/env node
/**
 * Get phone-registered device: Extract từ phone → Test login → Build pool
 *
 * Usage:
 *   node re/scripts/get_phone_device.mjs [method]
 *
 *   method: frida | adb | manual
 *   - frida: Dùng Frida hook (recommended, không cần root)
 *   - adb: Đọc từ SharedPreferences (cần adb)
 *   - manual: Nhập device_id + install_id tay
 */

import { execSync, spawn } from 'child_process';
import fs from 'fs';
import readline from 'readline';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck, userLogin } from '../src/login.mjs';

const method = process.argv[2] || 'frida';
const ACCOUNT = 'user5602420442843';
const PASS = '@33dp5YMAiCd';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function prompt(q) {
  return new Promise(r => rl.question(q, r));
}

async function extractViaMithproxy() {
  console.log('\n📱 METHOD: Proxy Capture (mitmproxy)\n');
  console.log('Steps:');
  console.log('  1. Install: pip install mitmproxy');
  console.log('  2. Start:   mitmproxy -p 8080');
  console.log('  3. Configure phone WiFi proxy to <PC_IP>:8080');
  console.log('  4. Open TikTok app');
  console.log('  5. Intercept /service/2/device_register/ response\n');

  const file = await prompt(
    'Paste captured device_id (from response JSON): '
  );
  const deviceId = file.trim();

  const file2 = await prompt('Paste install_id: ');
  const installId = file2.trim();

  if (!deviceId.match(/^\d{16,20}$/) || !installId.match(/^\d{16,20}$/)) {
    console.log('❌ Invalid format. device_id and install_id should be 16-20 digits');
    return null;
  }

  return { deviceId, installId };
}

async function extractViaFrida() {
  console.log('\n🔍 METHOD: Frida Hook\n');
  console.log('Steps:');
  console.log('  1. Install: pip install frida frida-tools');
  console.log('  2. Connect Android device via USB');
  console.log('  3. Script will attach to TikTok app\n');

  try {
    const result = new Promise((resolve, reject) => {
      const proc = spawn('python', ['re/scripts/extract_device_frida.py']);

      let output = '';
      let deviceId = null;
      let installId = null;

      proc.stdout.on('data', (data) => {
        const text = data.toString();
        console.log(text);
        output += text;

        // Parse output
        if (text.includes('[MMKV] device_id')) {
          deviceId = text.match(/device_id = (\d+)/)?.[1];
        }
        if (text.includes('[MMKV] install_id')) {
          installId = text.match(/install_id = (\d+)/)?.[1];
        }
      });

      proc.stderr.on('data', (data) => {
        console.log(data.toString());
      });

      proc.on('close', (code) => {
        if (code === 0 && deviceId && installId) {
          resolve({ deviceId, installId });
        } else {
          resolve(null);
        }
      });
    });

    return await result;
  } catch (err) {
    console.log(`❌ Frida error: ${err.message}`);
    return null;
  }
}

async function extractViaAdb() {
  console.log('\n📱 METHOD: ADB Shell\n');
  console.log('Steps:');
  console.log('  1. Connect device via USB');
  console.log('  2. Script reads SharedPreferences\n');

  try {
    const output = execSync('bash re/scripts/extract_device_adb.sh', {
      encoding: 'utf8',
    });
    console.log(output);

    const match = output.match(/Device ID: (\d+)[\s\S]*Install ID: (\d+)/);
    if (match) {
      return { deviceId: match[1], installId: match[2] };
    }
  } catch (err) {
    console.log(`❌ ADB error: ${err.message}`);
  }

  return null;
}

async function extractManual() {
  console.log('\n✍️  METHOD: Manual Input\n');

  const deviceId = await prompt('Enter device_id: ');
  const installId = await prompt('Enter install_id: ');

  if (!deviceId.match(/^\d{16,20}$/) || !installId.match(/^\d{16,20}$/)) {
    console.log('❌ Invalid format');
    return null;
  }

  return { deviceId, installId };
}

async function testDeviceLogin(deviceId, installId) {
  console.log('\n✅ Testing phone device login...\n');

  try {
    const dev = { device_id: deviceId, install_id: installId, id: {} };

    console.log('[1] Device setup...');
    const d = await dsign(dev);
    console.log(`    dsign s=${d.s}`);
    await warmup(dev, d);

    console.log('[2] Pre-check...');
    const pc = await preCheck(ACCOUNT, dev, d);
    if (pc.j?.message !== 'success') {
      console.log(`    ⚠️  Pre-check failed: ${pc.j?.data?.description?.slice(0, 60)}`);
      return false;
    }
    console.log('    ✓ Pre-check success');

    console.log('[3] Login...');
    const lg = await userLogin(ACCOUNT, PASS, dev, d);
    const ec = lg.j?.data?.error_code;
    const msg = lg.j?.message;

    if (msg === 'success') {
      console.log('    🎉 LOGIN SUCCESS!');
      return true;
    } else if (ec === 2135) {
      console.log('    ✓ Got 2135 (account flagged, but device TRUSTED)');
      return true;
    } else if (ec === 7) {
      console.log('    ❌ ec7 (device untrusted) — wrong device!');
      return false;
    } else {
      console.log(`    ❌ Login failed: ec=${ec}`);
      return false;
    }
  } catch (err) {
    console.log(`    ❌ Error: ${err.message}`);
    return false;
  }
}

async function main() {
  console.log('\n' + '='.repeat(60));
  console.log('📱 Extract Phone-Registered Device (Trusted)');
  console.log('='.repeat(60));

  let device = null;

  // Extract
  console.log(`\nMethod: ${method}`);
  switch (method.toLowerCase()) {
    case 'frida':
      device = await extractViaFrida();
      break;
    case 'adb':
      device = await extractViaAdb();
      break;
    case 'manual':
      device = await extractManual();
      break;
    case 'proxy':
    case 'mitmproxy':
      device = await extractViaMithproxy();
      break;
    default:
      console.log(`❌ Unknown method: ${method}`);
      process.exit(1);
  }

  if (!device) {
    console.log('\n❌ Failed to extract device_id');
    process.exit(1);
  }

  const { deviceId, installId } = device;

  // Test login
  console.log('\n' + '='.repeat(60));
  const testOk = await testDeviceLogin(deviceId, installId);

  if (!testOk) {
    console.log('\n⚠️  Device may not be phone-registered or trusted');
    console.log('    Try different method or check device\n');
    process.exit(1);
  }

  // Save
  console.log('\n' + '='.repeat(60));
  console.log('\n💾 Saving device...\n');

  fs.mkdirSync('re/out', { recursive: true });

  const deviceLine = `${deviceId}|${installId}`;
  fs.writeFileSync('re/out/phone_device.txt', deviceLine);
  console.log(`✓ Saved to: re/out/phone_device.txt`);
  console.log(`  ${deviceLine}`);

  // Append to pool
  const poolFile = 're/out/device_pool.txt';
  if (fs.existsSync(poolFile)) {
    const pool = fs.readFileSync(poolFile, 'utf8').trim().split('\n');
    if (!pool.includes(deviceLine)) {
      pool.push(deviceLine);
      fs.writeFileSync(poolFile, pool.join('\n'));
      console.log(`✓ Added to: re/out/device_pool.txt`);
    }
  } else {
    fs.writeFileSync(poolFile, deviceLine);
    console.log(`✓ Created: re/out/device_pool.txt`);
  }

  console.log('\n✅ Done!\n');
  console.log('Use device:');
  console.log(`  export RE_DEV="${deviceId}|${installId}"`);
  console.log(`  node re/tests/t_login_account.mjs`);

  rl.close();
}

main().catch(console.error);
