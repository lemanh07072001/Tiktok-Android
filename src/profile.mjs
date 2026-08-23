// re/src/profile.mjs — ĐA DẠNG fingerprint device (chống velocity-flag do mọi forge trùng SM-G930F).
//   Pick 1 profile/process (deterministic trong 1 lần chạy). Dùng bởi sign(UA) + device(register/dsign) + login(query).
import crypto from 'node:crypto';

// profile thật (model/brand/resolution/dpi/os_api/rom) — mỗi con 1 máy khác.
const PROFILES = [
  { model: 'SM-G930F', brand: 'samsung', mfr: 'samsung', res: '1440*2560', resv2: '1440*2560', dpi: 640, os_api: 28, osv: '9', rom: 'PPR1.180610.011', build: 'PPR1.180610.011' },
  { model: 'SM-G950F', brand: 'samsung', mfr: 'samsung', res: '1440*2960', resv2: '1440*2960', dpi: 640, os_api: 29, osv: '10', rom: 'QP1A.190711.020', build: 'QP1A.190711.020' },
  { model: 'SM-A515F', brand: 'samsung', mfr: 'samsung', res: '1080*2400', resv2: '1080*2400', dpi: 420, os_api: 30, osv: '11', rom: 'RP1A.200720.012', build: 'RP1A.200720.012' },
  { model: 'Redmi Note 8', brand: 'Xiaomi', mfr: 'Xiaomi', res: '1080*2340', resv2: '1080*2340', dpi: 440, os_api: 29, osv: '10', rom: 'QKQ1.190910.002', build: 'QKQ1.190910.002' },
  { model: 'Pixel 4', brand: 'google', mfr: 'Google', res: '1080*2280', resv2: '1080*2280', dpi: 440, os_api: 30, osv: '11', rom: 'RP1A.201005.004', build: 'RP1A.201005.004' },
  { model: 'CPH2185', brand: 'OPPO', mfr: 'OPPO', res: '720*1600', resv2: '720*1600', dpi: 280, os_api: 30, osv: '11', rom: 'RP1A.200720.011', build: 'RP1A.200720.011' },
  { model: 'V2027', brand: 'vivo', mfr: 'vivo', res: '1080*2400', resv2: '1080*2400', dpi: 480, os_api: 30, osv: '11', rom: 'RP1A.200720.012', build: 'RP1A.200720.012' },
];

// pick theo env RE_PROFILE (index) hoặc random 1 lần/process.
const idx = process.env.RE_PROFILE !== undefined ? Number(process.env.RE_PROFILE) % PROFILES.length : crypto.randomInt(PROFILES.length);
export const P = PROFILES[idx];

// UA khớp profile (version app từ RE_VER).
export function makeUA(appVc) {
  return `com.zhiliaoapp.musically/${appVc} (Linux; U; Android ${P.osv}; en; ${P.model}; Build/${P.build}; Cronet/TTNetVersion:41c3dc2f 2026-04-08 QuicVersion:f9fda2ef 2026-03-10)`;
}
export const RES_QUERY = P.res;   // "1440*2560" cho query resolution
