// t_compare_argus_feed.mjs — Đo x-argus LOGIN: synthesize (RAM stubs) vs full device-state-dir feed (file .msp_ read),
//   trên CÙNG genuine login request (_login450_extract.json, device 7632, khronos cố định → gorgon so được).
//   Mốc: genuine login x-argus = 752 char. Hỏi: feed có làm offline argus tiến gần 752 hơn 324 (synthesize) không?
//   ⚠️ CAVEAT: msstate extract là của device 7664922 (trill 45.7.3); DID request = 7632 (45.0.3) → device+version MISMATCH.
//      Kết quả = thăm dò upper-bound, KHÔNG phải proof genuine.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const UNIDBG = 'e:/tiktok_signer/mobile/unidbg';
const JAVA = 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot/bin/java.exe';
const MSSTATE = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/b2d0add6-5091-4b0a-93f5-07da2ea66a7a/scratchpad/msstate';

const g = JSON.parse(fs.readFileSync('e:/tiktok_signer/re/ground-truth/_login450_extract.json', 'utf8'));
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

fs.writeFileSync(path.join(UNIDBG, 'url.bin'), g.url, 'latin1');
fs.writeFileSync(path.join(UNIDBG, 'cookie.bin'), block, 'latin1');
const cp = 'target/classes;' + fs.readFileSync(path.join(UNIDBG, 'cp.txt'), 'utf8').trim();

const COMMON = {
  ...process.env, JAVA_HOME: 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot',
  SIGN: '1', FIXTIME: String(khronos), NO_COMPILE: '1',
  DID: '7632162877655729682', IID: '7654446515603801877',
};

const modes = {
  // M1 baseline reproduce t_compare_argus: synthesize (RAM stubs)
  'M1-SYN': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_STATE: '1', MSB_INITFLAG: '1', MSB_ROOT_EMPTY: '1' },
  // M2 feed-file: đọc file device-state thật (.msp_/.msf3/.mss_) thay RAM stub
  'M2-FEED-FILE': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE, MSB_VER: '45.7.3', MSB_VERCODE: '2024507030', MSB_DEVSTATE_VERBOSE: '1' },
  // M3 feed-net: M2 + thread collect → get_seed fire (dyn_seed vào state)
  'M3-FEED-NET': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE, MSB_VER: '45.7.3', MSB_VERCODE: '2024507030', MSB_NET: '1', MSB_THREADS: '1', MSB_THREADS_SECS: '12' },
};

console.log('genuine login: khronos=%d  gen_argus len=%d  gen_gorgon=%s\n', khronos, g.gen_argus.length, g.gen_gorgon);

for (const [name, env] of Object.entries(modes)) {
  let out = '';
  try {
    out = execFileSync(JAVA, ['-Djava.library.path=native', '-cp', cp, 'tt.Harness'],
      { cwd: UNIDBG, env: { ...COMMON, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024, timeout: 150000 });
  } catch (e) { out = (e.stdout || '') + (e.stderr || ''); }
  const blk = (out.match(/===SIGN_OUT===\r?\n([\s\S]*?)\r?\n===END===/) || [])[1] || '';
  const argus = (blk.match(/X-Argus\r?\n([^\r\n]+)/) || [])[1] || '';
  const gorgon = (blk.match(/X-Gorgon\r?\n([^\r\n]+)/) || [])[1] || '';
  const gsFired = /GET_SEED POST/.test(out);
  const gs200 = /GET_SEED POST[\s\S]*?resp code=200/.test(out);
  const mspReads = (out.match(/\[devstate\][^\n]*\.msp_[^\n]*/g) || []).length;
  const sdkNotInit = /SDK not init/.test(out);
  const gMatch = gorgon === g.gen_gorgon ? '✅GORGON-MATCH' : '❌gorgon≠';
  console.log(`── ${name} ──`);
  console.log(`   X-Argus len=${argus.length}  (genuine=752, baseline-syn=324)   ${gMatch} gorgon=${gorgon.slice(0, 24)}…`);
  console.log(`   X-Argus[:48]=${argus.slice(0, 48)}`);
  console.log(`   get_seed fired=${gsFired} 200=${gs200} | .msp_ reads=${mspReads} | SDK-not-init=${sdkNotInit}`);
  console.log('');
}
console.log('Δ vs genuine 752:  M1 baseline 324 (Δ=428). Xem M2/M3 có giảm Δ không.');
