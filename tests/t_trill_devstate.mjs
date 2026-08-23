// Verify alignment 45.7.3: signer TRILL (lib 45.7.3, MS_SIGN_OFF=0x9ecc0) baseline vs + device-state feed.
// Cùng FIXTIME → khác biệt x-argus CHỈ do device-state. So length (344 genuine) + value. Qua sign.mjs (production path).
import { signOffline } from '../../mobile/sign.mjs';

const STATE = process.env.STATE_DIR
  || 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/b2d0add6-5091-4b0a-93f5-07da2ea66a7a/scratchpad/msstate';
const FIX = 1721544000;
const DID = process.env.DID || '7664922';
const IID = process.env.IID || '7654446515603801877';

// Feed request (format sign function CHẤP NHẬN — device_register URL bị reject/null)
const URL = 'https://api22-normal-c-alisg.tiktokv.com/aweme/v2/feed/?aid=1233';
const HDR = 'cookie\r\nstore-idc=alisg';

const TRILL = {
  MS_VENDOR: 'libs_trill/', MS_LIBS: 'libs_trill', MS_SIGN_OFF: '0x9ecc0',
  MS_DISP_OFF: '0x11a1e0', MS_LICENSE_FILE: 'license_trill.json',
  DID, IID, NO_COMPILE: '1', MSB_FULLINIT: '1',
};
const DEVSTATE = {
  ...TRILL, MSB_KV: '1', MSB_DEVSTATE_DIR: STATE,
  MSB_VER: '45.7.3', MSB_VERCODE: '2024507030',
};
const L = (r, k) => (r?.[k] || '').length;

console.log('=== [1] TRILL 45.7.3 baseline (KHÔNG device-state) ===');
const r1 = await signOffline(URL, HDR, FIX, TRILL);
console.log('X-Argus len=%d  X-Ladon len=%d  X-Gorgon=%s', L(r1, 'X-Argus'), L(r1, 'X-Ladon'), r1['X-Gorgon']);

console.log('\n=== [2] TRILL 45.7.3 + device-state (msstate, ver=45.7.3) ===');
const r2 = await signOffline(URL, HDR, FIX, DEVSTATE);
console.log('X-Argus len=%d  X-Ladon len=%d  X-Gorgon=%s', L(r2, 'X-Argus'), L(r2, 'X-Ladon'), r2['X-Gorgon']);

console.log('\n=== KẾT LUẬN ===');
console.log('X-Argus: baseline=%d  +state=%d  Δ=%d', L(r1, 'X-Argus'), L(r2, 'X-Argus'), L(r2, 'X-Argus') - L(r1, 'X-Argus'));
console.log('x-argus đổi value:', r1['X-Argus'] !== r2['X-Argus'] ? 'CÓ ✓ (device-state được dùng ở version 45.7.3)' : 'KHÔNG');
