// TEST QUYẾT ĐỊNH: x-argus offline (net-signer, có dyn_seed thật) có được server TikTok chấp nhận không?
// Ký lại request feed THẬT của device 7664922 bằng unidbg net-signer (chạy harness TRỰC TIẾP, stdin ignore để né debugger)
// → POST → xem response. Feed guest block="cookie" (không session) → isolate signature-validity.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const SP = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/b2d0add6-5091-4b0a-93f5-07da2ea66a7a/scratchpad';
const UNIDBG = 'e:/tiktok_signer/mobile/unidbg';
const JAVA = 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot/bin/java.exe';
let url = fs.readFileSync(SP + '/feed_url.txt', 'utf8').trim();

const nowMs = Date.now(), nowS = Math.floor(nowMs / 1000);
url = url.replace(/_rticket=\d+/, '_rticket=' + nowMs).replace(/([&?])ts=\d+/, '$1ts=' + nowS);

const COOKIE_BLOCK = 'cookie\r\nstore-idc=alisg';  // block metasec ký (phải khớp header cookie gửi đi)
fs.writeFileSync(path.join(UNIDBG, 'url.bin'), url, 'latin1');
fs.writeFileSync(path.join(UNIDBG, 'cookie.bin'), COOKIE_BLOCK, 'latin1');

const cp = 'target/classes;' + fs.readFileSync(path.join(UNIDBG, 'cp.txt'), 'utf8').trim();
const env = {
  ...process.env, JAVA_HOME: 'C:/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot',
  SIGN: '1', FIXTIME: String(nowS), NO_COMPILE: '1',
  MS_VENDOR: 'libs_trill/', MS_LIBS: 'libs_trill', MS_SIGN_OFF: '0x9ecc0',
  MS_DISP_OFF: '0x11a1e0', MS_LICENSE_FILE: 'license_mus4573.json',
  MSB_DEVSTATE_DIR: SP + '/msstate', MSB_VER: '45.7.3', MSB_VERCODE: '2024507030',
  MSB_FULLINIT: '1', MSB_KV: '1', MSB_NET: '1', MSB_THREADS: '1', MSB_THREADS_SECS: '12',
  DID: '7664922900961740308', IID: '7664924131670378260',
};
console.log('[*] ký feed offline (net-signer, harness trực tiếp, ts=%d)...', nowS);
let out = '';
try {
  out = execFileSync(JAVA, ['-Djava.library.path=native', '-cp', cp, 'tt.Harness'],
    { cwd: UNIDBG, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024, timeout: 90000 });
} catch (e) { out = (e.stdout || '') + (e.stderr || ''); }

const blk = (out.match(/===SIGN_OUT===\r?\n([\s\S]*?)\r?\n===END===/) || [])[1] || '';
const pick = (h) => (blk.match(new RegExp(h + '\\r?\\n([^\\r\\n]+)')) || [])[1];
const sig = { 'X-Gorgon': pick('X-Gorgon'), 'X-Khronos': pick('X-Khronos'), 'X-Ladon': pick('X-Ladon'), 'X-Argus': pick('X-Argus') };
const gsOk = /GET_SEED POST/.test(out) && /resp code=200/.test(out);
console.log('[*] get_seed trong unidbg: %s | X-Argus len=%d  X-Gorgon=%s', gsOk ? 'OK 200' : 'KHÔNG', (sig['X-Argus'] || '').length, sig['X-Gorgon']);
if (!sig['X-Gorgon']) { console.log('[!] ký thất bại. tail harness:\n', out.slice(-500)); process.exit(1); }

const UA = 'com.zhiliaoapp.musically/2024507030 (Linux; U; Android 9; en; SM-G930F; Build/PPR1.180610.011; Cronet/TTNetVersion:8e2f1a20 2024-01-01)';
for (const method of ['POST', 'GET']) {
  try {
    const headers = { 'user-agent': UA, 'accept-encoding': 'gzip', 'x-ss-req-ticket': String(nowMs), 'cookie': 'store-idc=alisg', ...sig };
    const opt = { method, headers };
    if (method === 'POST') { headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'; opt.body = ''; }
    const r = await fetch(url, opt);
    const txt = await r.text();
    const m = txt.match(/"status_code"\s*:\s*(-?\d+)/);
    console.log(`\n=== ${method} HTTP ${r.status} | status_code=${m ? m[1] : '?'} | aweme_list=${txt.includes('aweme_list')} ===`);
    console.log('resp[:400]:', txt.slice(0, 400).replace(/[^\x20-\x7e]/g, '.'));
    if (r.status === 200 && (txt.includes('aweme_list') || (m && m[1] === '0'))) { console.log('\n✅✅ SERVER CHẤP NHẬN x-argus offline (có dyn_seed)!'); break; }
  } catch (e) { console.log(`[${method}] ERR`, e.message); }
}
