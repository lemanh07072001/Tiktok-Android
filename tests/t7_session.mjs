// re/tests/t7_session.mjs — xài account qua API bằng session (no-phone). Chạy: node re/tests/t7_session.mjs <combo_file>
import '../src/net.mjs';
import fs from 'node:fs';
import { callAuthed, sessionFromCombo } from '../src/session.mjs';

const line = fs.readFileSync(process.argv[2], 'utf8').split('\n')[0];
const s = sessionFromCombo(line);
console.log('[t7] session uid=' + s.uid + ' | cookie có sessionid:', /sessionid=/.test(s.cookie));

const r = await callAuthed(s, '/passport/account/info/v2/', { extraQuery: { scene: 'ocl', multi_login: 1, account_sdk_source: 'app' } });
console.log('[t7] account/info → STATUS', r.status);
const d = r.j?.data || {};
if (d.username || d.user_id) {
  console.log('  ✅ XÀI ĐƯỢC QUA API (no-phone): username=' + d.username + ' uid=' + d.user_id + ' store=' + d.store_country + ' app_id=' + d.app_id);
  process.exit(0);
} else {
  console.log('  ❌ resp:', (r.txt || '').slice(0, 200));
  process.exit(1);
}
