// replay_getseed.mjs — gui lai request get_seed (metasec dung) tu client cua MINH.
// Chung minh: tu goi /ms/get_seed va nhan 176B dyn_seed, khong qua app.
import https from 'node:https';
import zlib from 'node:zlib';
import fs from 'node:fs';
import { URL } from 'node:url';

const rec = JSON.parse(fs.readFileSync('e:/tiktok_signer/getseed_replay.json', 'utf8'));
const body = Buffer.from(rec.body_b64, 'base64');
const u = new URL(rec.url);

// tuoi cua request (x-khronos) so voi bay gio
const now = Math.floor(Date.now() / 1000);
const age = rec.khronos ? (now - Number(rec.khronos)) : NaN;
console.log(`[*] URL: ${u.host}${u.pathname}`);
console.log(`[*] Body: ${body.length}B | x-khronos=${rec.khronos} | tuoi=${age}s`);
console.log(`[*] Headers: ${Object.keys(rec.headers).length} (co x-argus=${!!rec.headers['x-argus']||!!rec.headers['X-Argus']})`);

const headers = { ...rec.headers, 'content-length': body.length, 'accept-encoding': 'gzip, deflate, br' };

const req = https.request({
  method: rec.method,
  host: u.host,
  path: u.pathname + u.search,
  headers,
  rejectUnauthorized: false,   // client cua ta, khong pin
}, (res) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    let buf = Buffer.concat(chunks);
    const enc = (res.headers['content-encoding'] || '').toLowerCase();
    try {
      if (enc.includes('br')) buf = zlib.brotliDecompressSync(buf);
      else if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
      else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
    } catch (e) { console.log('[!] decompress loi:', e.message); }

    console.log(`\n[<] HTTP ${res.statusCode} | body ${buf.length}B | x-tt-logid=${res.headers['x-tt-logid'] || '-'}`);
    console.log('[<] body hex:', buf.subarray(0, 200).toString('hex'));

    // decode protobuf tim field6 (seed)
    const seed = extractSeed(buf);
    if (seed) {
      console.log(`\n=== THANH CONG: server tra dyn_seed cho CLIENT CUA TA ===`);
      console.log(`dyn_seed = ${seed.length}B`);
      console.log('hex   :', seed.toString('hex'));
      console.log('base64:', seed.toString('base64'));
      fs.writeFileSync('e:/tiktok_signer/SELF_FETCHED_SEED.txt', 'hex=' + seed.toString('hex') + '\n');
    } else {
      console.log('\n[!] Khong thay seed 176B. Body co the la loi/tu choi. Xem hex tren.');
      // thu in text neu la JSON loi
      const t = buf.toString('utf8').replace(/[^\x20-\x7e]/g, '.');
      if (/[a-zA-Z]{4}/.test(t)) console.log('[!] body text:', t.slice(0, 300));
    }
  });
});
req.on('error', (e) => console.log('[!] request loi:', e.message));
req.write(body);
req.end();

// protobuf: tim field bytes lon nhat (~176B) = seed
function extractSeed(b) {
  let i = 0, best = null;
  const rv = () => { let s = 0, v = 0; while (i < b.length) { const c = b[i++]; v |= (c & 0x7f) << s; if (!(c & 0x80)) break; s += 7; } return v >>> 0; };
  try {
    while (i < b.length) {
      const key = rv(); const wt = key & 7;
      if (wt === 0) rv();
      else if (wt === 2) { const ln = rv(); const d = b.subarray(i, i + ln); i += ln; if (!best || d.length > best.length) best = d; }
      else if (wt === 5) i += 4;
      else if (wt === 1) i += 8;
      else break;
    }
  } catch { /* */ }
  return best && best.length >= 120 ? best : null;
}
