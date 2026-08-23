// Diagnose "Maximum number of attempts reached" — test 3 scenarios
import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { warmup, preCheck } from '../src/login.mjs';

const USER1 = 'user5602420442843';  // Target account
const USER2 = 'user2566';           // Different account (test if throttle is per-account)

// Device 1: Forge (fresh-registered)
const dev1 = { device_id: '7654283410013816340', install_id: '7654515472762717972', id: {} };

// Device 2: Minted (trusted)
const dev2 = { device_id: '7654265922945893909', install_id: '7654515472762717972', id: {} };

async function runTest(label, user, dev) {
  try {
    const d = await dsign(dev);
    await warmup(dev, d);
    const result = await preCheck(user, dev, d);

    console.log(`\n${label}`);
    console.log('  User:', user);
    console.log('  Device:', dev.device_id);
    console.log('  Status:', result.status);
    console.log('  Message:', result.j?.message);

    if (result.j?.data?.description) {
      console.log('  Description:', result.j.data.description.slice(0, 80));
    }

    return result;
  } catch (err) {
    console.log(`\n${label}`);
    console.log('  Error:', err.message);
    return null;
  }
}

async function runDiagnosis() {
  console.log('\n🔍 THROTTLE DIAGNOSIS: 3 scenarios\n');
  console.log('='.repeat(70));

  console.log('\n📋 SCENARIO A: user5602 on device 1 (forge)');
  const a1 = await runTest('A1:', USER1, dev1);

  console.log('\n  Waiting 3s...');
  await new Promise(r => setTimeout(r, 3000));

  const a2 = await runTest('A2 (retry):', USER1, dev1);

  console.log('\n\n📋 SCENARIO B: user2566 on device 1 (forge) — different account, same device/IP');
  const b = await runTest('B:', USER2, dev1);

  console.log('\n\n📋 SCENARIO C: user5602 on device 2 (minted) — same account, different device');
  const c = await runTest('C:', USER1, dev2);

  console.log('\n\n' + '='.repeat(70));
  console.log('\n📊 INTERPRETATION:\n');

  const a1Success = a1?.j?.message === 'success';
  const a2Success = a2?.j?.message === 'success';
  const bSuccess = b?.j?.message === 'success';
  const cSuccess = c?.j?.message === 'success';

  if (a1Success || a2Success) {
    console.log('✅ Account can be pre-checked');
  } else {
    console.log('❌ Both A1 & A2 failed → throttle active');
  }

  if (bSuccess) {
    console.log('✅ Different account works on same device/IP → throttle is ACCOUNT-SPECIFIC');
  } else if (!a1Success && !bSuccess) {
    console.log('❌ Both accounts fail on same device/IP → throttle is IP or DEVICE-SPECIFIC');
  }

  if (cSuccess && !a1Success) {
    console.log('✅ Same account works on different device → throttle is DEVICE-SPECIFIC');
  } else if (!cSuccess && !a1Success) {
    console.log('❌ Account fails on both devices → throttle is ACCOUNT-SPECIFIC (or IP-wide)');
  }

  console.log('\n📌 SUMMARY:');
  console.log(`  A1: ${a1Success ? '✓' : '✗'} (user5602 + device1)`);
  console.log(`  A2: ${a2Success ? '✓' : '✗'} (retry same)`);
  console.log(`  B:  ${bSuccess ? '✓' : '✗'} (user2566 + device1)`);
  console.log(`  C:  ${cSuccess ? '✓' : '✗'} (user5602 + device2)`);
}

runDiagnosis().catch(console.error);
