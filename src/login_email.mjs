// re/src/login_email.mjs — Task 6: LOGIN bằng EMAIL-CODE (tự verify → bỏ qua 2135).
//   Dùng cho account bị flag (password-login ra 2135). Trusted device + email-code → SUCCESS.
//   Bám ground-truth mobile/login_2135.mjs (endpoint + params proven). enc = XOR 0x05 hex.
//   Reader email = bridge mobile/hotmail.mjs (infra mail client, không phải RE logic).
import { passportCall, enc, JAR, cookieHdr } from './login.mjs';

// send_code type 3436 scene login (proven params). Trusted device → success; forge → 1105 (captcha).
export async function sendCode(email, dev, d) {
  return passportCall(dev, d, '/passport/email/send_code/', {
    params: { account_sdk_source: 'app', rule_strategies: '2', mix_mode: '1', enable_account_selection: '1', multi_login: '1', type: '3436', email: enc(email), email_theme: '2', use_passport_ticket: '1', scene: '3' },
  });
}

// code_login — email-code TỰ verify. account chưa-2135 → SUCCESS thẳng. account cần password-verify → 2135+aaas_ticket (webview, bất khả pure-API).
export async function codeLogin(email, code, dev, d) {
  return passportCall(dev, d, '/passport/app/email/code_login/', {
    params: { code: enc(code), account_sdk_source: 'app', mix_mode: '1', enable_account_selection: '1', multi_login: '1', type: '3436', email: enc(email) },
  });
}

// available_ways sau send_code (app làm — có thể khởi tạo verify-session)
export async function availableWays(dev, d, passportTicket) {
  return passportCall(dev, d, '/passport/auth/available_ways/', { method: 'GET', extraQuery: { passport_ticket: passportTicket } });
}

// build session object từ JAR sau login SUCCESS
export function sessionFrom(lg, dev) {
  const cookie = cookieHdr();
  const uid = lg.j?.data?.user_id_str || lg.j?.data?.user_id || '';
  return { cookie, deviceId: dev.device_id, iid: dev.install_id, xtt: lg.xtt || '', uid, ts: Date.now() };
}
