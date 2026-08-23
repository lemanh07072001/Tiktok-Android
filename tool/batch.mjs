// re/tool/batch.mjs — LAUNCHER: đọc account.txt + proxy.txt, mở MỖI account 1 cửa sổ CMD riêng
//   (số cmd = số account), mỗi cửa sổ 1 PROXY_URL riêng. Chạy: node batch.mjs   (hoặc run.cmd)
//   --dry : chỉ in kế hoạch ghép account↔proxy, KHÔNG mở cửa sổ.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const p = (f) => path.join(HERE, f);
const DRY = process.argv.includes('--dry');

function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
}

// proxy: "http://user:pass@host:port" | "host:port:user:pass" | "host:port"
function toProxyUrl(line) {
  if (/:\/\//.test(line)) return line;
  const a = line.split(':');
  if (a.length === 4) return `http://${a[2]}:${a[3]}@${a[0]}:${a[1]}`;
  if (a.length === 2) return `http://${a[0]}:${a[1]}`;
  return line;
}

// fingerprint (model/brand/res) ổn định RIÊNG theo account — stable hash, profile.mjs mod theo số profile.
function profIdx(user) { let h = 5381; for (const c of String(user)) h = ((h * 33) ^ c.charCodeAt(0)) >>> 0; return h; }

// config.txt: KEY=VALUE (METASEC_ORACLE, RE_VER, STAGGER_MS...)
function readConfig() {
  const cfg = {};
  for (const l of readLines(p('config.txt'))) { const i = l.indexOf('='); if (i > 0) cfg[l.slice(0, i).trim()] = l.slice(i + 1).trim(); }
  return cfg;
}

const accounts = readLines(p('account.txt'));
const proxies = readLines(p('proxy.txt')).map(toProxyUrl);
const cfg = readConfig();
const STAGGER = parseInt(cfg.STAGGER_MS || '1500', 10);
const oracle = process.env.METASEC_ORACLE || cfg.METASEC_ORACLE || '';
const worker = p('worker.mjs');
const PER_ROW = parseInt(cfg.PER_ROW || '5', 10);                          // số cmd / hàng
const TILE = !process.argv.includes('--no-tile') && (cfg.TILE || '1') !== '0';
const COLS = parseInt(cfg.COLS || '50', 10), LINES = parseInt(cfg.LINES || '52', 10);
const PREFIX = 'T' + process.pid + '_';                                    // scope title theo run

if (!accounts.length) { console.error('⚠ account.txt trống — thêm mỗi dòng 1 account: user|pass|email|mailpass'); process.exit(2); }
if (!proxies.length) console.warn('⚠ proxy.txt trống → chạy KHÔNG proxy (dễ dính ec7 velocity, nên có IP sạch/account).');

console.log(`── launcher: ${accounts.length} account · ${proxies.length} proxy · signer=${oracle || 'unidbg-offline'} · ${PER_ROW}/hàng · stagger=${STAGGER}ms ${DRY ? '(DRY)' : ''}`);

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

for (let i = 0; i < accounts.length; i++) {
  const line = accounts[i];
  const user = line.split('|')[0];
  const proxyUrl = proxies.length ? proxies[i % proxies.length] : '';
  const shownProxy = proxyUrl.replace(/\/\/[^@]*@/, '//***@') || '(none)';
  console.log(`  #${i + 1} ${user}  ←  ${shownProxy}`);
  if (DRY) continue;

  const title = (PREFIX + (i + 1) + '_' + user).replace(/[^\w]/g, '_').slice(0, 44);
  const inner = `chcp 65001>nul && mode con: cols=${COLS} lines=${LINES} && node ${worker}`;
  const cmdLine = `start "${title}" cmd /k "${inner}"`;
  spawn(cmdLine, {
    shell: true, stdio: 'ignore', windowsHide: false,
    env: { ...process.env, ACCOUNT: line, PROXY_URL: proxyUrl, RE_PROFILE: String(profIdx(user)), ...(oracle ? { METASEC_ORACLE: oracle } : {}), ...(cfg.RE_VER ? { RE_VER: cfg.RE_VER } : {}) },
  });
  await sleep(STAGGER);
}

// xếp lưới PER_ROW cửa/hàng (chỉ cửa sổ của run này — prefix T<pid>_)
if (TILE && !DRY) {
  await sleep(1200);
  const ps1 = p('tile.ps1');
  console.log(`\n⊞ xếp cửa sổ ${PER_ROW}/hàng…`);
  spawn(`powershell -NoProfile -ExecutionPolicy Bypass -File "${ps1}" -PerRow ${PER_ROW} -Prefix "${PREFIX}"`, { shell: true, stdio: 'inherit' });
}

console.log(DRY ? '\n(DRY) không mở cửa sổ. Bỏ --dry để chạy thật.' : `\n✓ đã mở ${accounts.length} cửa sổ CMD (${PER_ROW}/hàng). Mỗi cửa sổ tự chạy login + hiện info; kết quả lưu re/tool/out/.`);
