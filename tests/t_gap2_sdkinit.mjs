// t_gap2_sdkinit.mjs — GAP #2: ep metasec SDK init offline -> x-argus co day (344) khong?
//   Do do dai x-argus cho CUNG url device_register voi tung to hop co MSB_*. Khong tao device moi.
//   Ky vong: neu SDK init OK -> "SDK not init" bien mat + x-argus dai ra (324 -> ~344).
import { signOffline } from '../../mobile/sign.mjs';
import { UA } from '../src/sign.mjs';
import crypto from 'node:crypto';

const nowS = Math.floor(Date.now() / 1000), nowMs = Date.now();
const url = 'https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&os=android&aid=1233&version_code=2024500030&version_name=45.0.3&channel=googleplay&openudid=' + crypto.randomBytes(8).toString('hex') + '&cdid=' + crypto.randomUUID() + '&_rticket=' + nowMs + '&ts=' + nowS;
const body = JSON.stringify({ header: { os: 'Android', aid: 1233 }, magic_tag: 'ss_app_log', _gen_time: nowMs });
const stub = crypto.createHash('md5').update(body).digest('hex').toUpperCase();
const block = ['x-ss-stub', stub, 'content-type', 'application/json; charset=utf-8', 'x-ss-req-ticket', String(nowMs), 'x-tt-dm-status', 'login=0;ct=0;rt=7', 'sdk-version', '2', 'passport-sdk-version', '1', 'user-agent', UA].join('\r\n');

const combos = [
  ['baseline (khong co)', {}],
  ['INITFLAG', { MSB_INITFLAG: '1' }],
  ['INITFLAG+KV', { MSB_INITFLAG: '1', MSB_KV: '1' }],
  ['INITFLAG+KV+STATE+ROOT', { MSB_INITFLAG: '1', MSB_KV: '1', MSB_STATE: '1', MSB_ROOT_EMPTY: '1' }],
];

console.log('GAP#2: x-argus len theo to hop co (genuine device_register = 344)\n');
for (const [name, env] of combos) {
  try {
    const sig = signOffline(url, block, nowS, env);
    const xa = sig['X-Argus'] || '', xl = sig['X-Ladon'] || '', xg = sig['X-Gorgon'] || '';
    console.log(`  ${name.padEnd(26)} x-argus=${String(xa.length).padStart(3)}  x-ladon=${xl.length}  x-gorgon=${xg.length}`);
  } catch (e) {
    console.log(`  ${name.padEnd(26)} ERR ${e.message.slice(0, 120).replace(/\n/g, ' ')}`);
  }
}
