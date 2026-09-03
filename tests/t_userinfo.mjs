// t_userinfo.mjs — lấy CHI TIẾT thông tin user từ session (authenticated API).
//   node re/tests/t_userinfo.mjs [session_file]
import '../src/net.mjs';
import fs from 'node:fs';
import { callAuthed } from '../src/session.mjs';

const ATTK = 'C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk';
Object.assign(process.env, { MSB_DEVSTATE_DIR: `${ATTK}/msstate_7665668`, MS_VENDOR: 'libs_trill/', MS_LIBS: 'libs_trill', MS_SIGN_OFF: '0x9ecc0', MS_DISP_OFF: '0x11a1e0', MS_LICENSE_FILE: 'license_mus4573.json', MSB_VER: '45.7.3', MSB_VERCODE: '2024507030', MSB_FULLINIT: '1', MSB_KV: '1' });

const file = process.argv[2] || 're/out/session_7543633780763870264.json';
const s = JSON.parse(fs.readFileSync(file, 'utf8'));
console.log('=== SESSION uid=%s device=%s ===\n', s.uid, s.deviceId);

const show = (label, r) => {
  console.log('── %s (http=%s) ──', label, r.status);
  if (r.j?.data) console.log(JSON.stringify(r.j.data, null, 1).slice(0, 2000));
  else console.log((r.txt || '').slice(0, 500));
  console.log();
};

// 1) passport account info (email/phone/verify status)
show('passport/account/info', await callAuthed(s, '/passport/account/info/v2/', { extraQuery: { scene: 'normal' } }).catch((e) => ({ status: 'ERR', txt: e.message })));
// 2) aweme user profile (follower/following/aweme count, nickname, bio)
const PHOST_AWEME = 'api22-normal-c-alisg.tiktokv.com';
show('aweme/user/settings', await callAuthed(s, '/aweme/v1/user/settings/', {}).catch((e) => ({ status: 'ERR', txt: e.message })));
show('aweme/v1/user/profile/self', await callAuthed(s, '/aweme/v1/user/profile/self/', { extraQuery: { user_id: s.uid } }).catch((e) => ({ status: 'ERR', txt: e.message })));
