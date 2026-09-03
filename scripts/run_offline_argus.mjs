// run_offline_argus.mjs — Chay X-Argus OFFLINE (unidbg) o nhieu MODE + do LENGTH vs phone.
//   Muc dich: xem offline ra gi, thieu bao nhieu so voi phone (gap = device-state).
//   Signer that o /e/tiktok_signer/mobile/sign.mjs (folder nay detached khoi mobile/).
import fs from 'node:fs';
import path from 'node:path';

const SIGN = 'file:///E:/tiktok_signer/mobile/sign.mjs';
const { signOffline } = await import(SIGN);

const g = JSON.parse(fs.readFileSync('ground-truth/_login450_extract.json', 'utf8'));
const block = [
  'x-ss-stub', g.stub,
  'content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
  'x-ss-req-ticket', g.ticket,
  'x-tt-token', g.ttToken,
  'cookie', g.cookie,
  'user-agent', g.ua,
  'sdk-version', '2', 'passport-sdk-version', '1',
].join('\r\n');
const kh = parseInt(g.khronos, 10);

const DID = '7632162877655729682', IID = '7654446515603801877';
const MSSTATE = path.resolve('ground-truth/msstate_7664922');
const base = { NO_COMPILE: '1', DID, IID, MSB_VER: '45.7.3' };

const MODES = {
  A_plain:        { ...base },
  B_fullinit:     { ...base, MSB_FULLINIT: '1', MSB_KV: '1', MSB_STATE: '1', MSB_INITFLAG: '1', MSB_ROOT_EMPTY: '1' },
  C_devstate:     { ...base, MSB_FULLINIT: '1', MSB_KV: '1', MSB_STATE: '1', MSB_INITFLAG: '1', MSB_ROOT_EMPTY: '1',
                    MSB_DEVSTATE_DIR: MSSTATE, MSB_DEVSTATE_VERBOSE: process.env.VERBOSE ? '1' : '' },
};

const rawLen = (b64) => { try { return Buffer.from(b64, 'base64').length; } catch { return -1; } };

console.log('phone genuine (45.0.3) X-Argus: b64=%d raw=%d', g.gen_argus.length, rawLen(g.gen_argus));
console.log('phone genuine (45.7.3) X-Argus: raw~594 (tu genuine_xargus_45.7.3.json, 5 mau)\n');

const only = process.argv[2];
for (const [name, env] of Object.entries(MODES)) {
  if (only && name !== only) continue;
  process.stdout.write(`[${name}] signing... `);
  const t0 = Date.now();
  try {
    const sig = signOffline(g.url, block, kh, env);
    const xa = sig['X-Argus'] || '';
    console.log(`OK ${Date.now()-t0}ms`);
    console.log(`   X-Argus  b64=${xa.length} raw=${rawLen(xa)}  prefix=${xa.slice(0,24)}`);
    console.log(`   X-Gorgon ${(sig['X-Gorgon']||'').slice(0,32)}  X-Ladon raw=${rawLen(sig['X-Ladon']||'')}`);
    fs.writeFileSync(`out/offline_argus_${name}.json`, JSON.stringify({ mode:name, env, ...sig }, null, 1));
  } catch (e) {
    console.log(`FAIL ${Date.now()-t0}ms`);
    console.log('   ' + String(e.message || e).split('\n').slice(0,3).join('\n   '));
  }
}
