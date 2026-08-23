// t_compare_argus.mjs — So x-argus/gorgon/ladon OFFLINE (unidbg 45.0.x) vs GENUINE phone 45.0.3
//   (ground-truth/03_login_450_genuine.json). Cung version -> so byte-exact duoc.
//   Tai ky DUNG request genuine: url + block + khronos + device-state (7632) + MSB_FULLINIT.
import { signOffline } from '../../mobile/sign.mjs';
import fs from 'node:fs';

const g = JSON.parse(fs.readFileSync('ground-truth/_login450_extract.json', 'utf8'));
// dung block metasec chuan (re/src/sign.mjs metasecBlock) voi GIA TRI genuine
const block = [
  'x-ss-stub', g.stub,
  'content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
  'x-ss-req-ticket', g.ticket,
  'x-tt-token', g.ttToken,
  'cookie', g.cookie,
  'user-agent', g.ua,
  'sdk-version', '2', 'passport-sdk-version', '1',
].join('\r\n');

const khronos = parseInt(g.khronos, 10);   // 1783795608
console.log('[compare] khronos=%s device=7632 url_len=%d block_len=%d', khronos, g.url.length, block.length);

const env = { MSB_FULLINIT: '1', MSB_KV: '1', MSB_STATE: '1', MSB_INITFLAG: '1', MSB_ROOT_EMPTY: '1',
              DID: '7632162877655729682', IID: '7654446515603801877', NO_COMPILE: '1' };
const sig = signOffline(g.url, block, khronos, env);

const cmp = (name, off, gen) => {
  const m = off === gen;
  const pre = (s) => (s || '').slice(0, 40);
  console.log(`\n${name}: ${m ? '✅ MATCH byte-exact' : '❌ KHAC'}`);
  console.log(`  offline (len=${(off || '').length}): ${pre(off)}${(off || '').length > 40 ? '...' : ''}`);
  console.log(`  genuine (len=${(gen || '').length}): ${pre(gen)}${(gen || '').length > 40 ? '...' : ''}`);
};
cmp('X-Gorgon', sig['X-Gorgon'], g.gen_gorgon);
cmp('X-Ladon', sig['X-Ladon'], g.gen_ladon);
cmp('X-Argus', sig['X-Argus'], g.gen_argus);
console.log('\nX-Khronos offline=%s genuine=%s', sig['X-Khronos'], g.khronos);
