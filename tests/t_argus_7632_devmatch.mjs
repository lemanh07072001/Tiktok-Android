// t_argus_7632_devmatch.mjs — device-match measurement sạch nhất có thể với genuine 752 (device 7632, 45.0.3):
//   lib 45.0.x (default VENDOR) + version 45.0.3 (KHÔNG override MSB_VER) + DID 7632 + device-state phone (msstate).
//   Giả định: .msp_ device-seed bound theo PHONE (cùng .msp_ qua 2 bản extract) → msstate (phone ce031603) dùng được cho 7632.
//   ⚠️ Caveat: msstate extract từ app trill 45.7.3 + .msp_ refresh mỗi cold-start (drift) → byte-exact bất khả, chỉ đo LENGTH.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const UNIDBG = 'e:/tiktok_signer/mobile/unidbg';
const JAVA = 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot/bin/java.exe';
const MSSTATE = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/b2d0add6-5091-4b0a-93f5-07da2ea66a7a/scratchpad/msstate';

const g = JSON.parse(fs.readFileSync('e:/tiktok_signer/re/ground-truth/_login450_extract.json', 'utf8'));
const block = ['x-ss-stub', g.stub, 'content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
  'x-ss-req-ticket', g.ticket, 'x-tt-token', g.ttToken, 'cookie', g.cookie, 'user-agent', g.ua,
  'sdk-version', '2', 'passport-sdk-version', '1'].join('\r\n');
const khronos = parseInt(g.khronos, 10);
fs.writeFileSync(path.join(UNIDBG, 'url.bin'), g.url, 'latin1');
fs.writeFileSync(path.join(UNIDBG, 'cookie.bin'), block, 'latin1');
const cp = 'target/classes;' + fs.readFileSync(path.join(UNIDBG, 'cp.txt'), 'utf8').trim();

// version 45.0.3 = default (KHÔNG set MSB_VER/MSB_VERCODE) → khớp genuine 752
const COMMON = { ...process.env, JAVA_HOME: 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot',
  SIGN: '1', FIXTIME: String(khronos), NO_COMPILE: '1', DID: '7632162877655729682', IID: '7654446515603801877' };

const modes = {
  'M1-SYN-4503': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_STATE: '1', MSB_INITFLAG: '1', MSB_ROOT_EMPTY: '1' },
  'M2-FILE-4503': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE },
  'M3-NET-4503': { MSB_FULLINIT: '1', MSB_KV: '1', MSB_DEVSTATE_DIR: MSSTATE, MSB_NET: '1', MSB_THREADS: '1', MSB_THREADS_SECS: '12' },
};

console.log('genuine 752: device 7632, 45.0.3, khronos=%d, gen_argus len=%d\n', khronos, g.gen_argus.length);
for (const [name, env] of Object.entries(modes)) {
  let out = '';
  try { out = execFileSync(JAVA, ['-Djava.library.path=native', '-cp', cp, 'tt.Harness'],
    { cwd: UNIDBG, env: { ...COMMON, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024, timeout: 150000 });
  } catch (e) { out = (e.stdout || '') + (e.stderr || ''); }
  const blk = (out.match(/===SIGN_OUT===\r?\n([\s\S]*?)\r?\n===END===/) || [])[1] || '';
  const argus = (blk.match(/X-Argus\r?\n([^\r\n]+)/) || [])[1] || '';
  const gorgon = (blk.match(/X-Gorgon\r?\n([^\r\n]+)/) || [])[1] || '';
  const gs200 = /GET_SEED POST[\s\S]*?resp code=200/.test(out);
  const msp = (out.match(/\[devstate\][^\n]*\.msp_[^\n]*/g) || []).length;
  const ver = (out.match(/MS\.b\(cmd=0x1000011[\s\S]*?=> "([^"]+)"/) || [])[1] || (out.includes('45.0.3') ? '45.0.3?' : '?');
  console.log(`── ${name} ──  X-Argus len=${argus.length}  (genuine=752)  gorgon=${gorgon.slice(0,20)}…  get_seed200=${gs200} .msp_reads=${msp}`);
}
