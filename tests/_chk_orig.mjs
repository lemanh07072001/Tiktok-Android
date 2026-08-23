import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';
// identity GOC ma device 7664922 dang ky lan dau
const dev = { device_id:'7664922900961740308', install_id:'7664924131670378260',
  openudid:'8f6453d9327f0db3', cdid:'60c008e3-6bef-418d-beda-bffca20321c8',
  id:{ openudid:'8f6453d9327f0db3', cdid:'60c008e3-6bef-418d-beda-bffca20321c8', clientudid:'bee6562e-ac0b-4eb5-bc56-25bd5a9602cd', google_aid:'5542723c-a932-41db-87d3-1aaa3aba7a99' } };
const d = await dsign(dev).catch(e=>({_err:e}));
console.log('[dsign GOC] s=%s token=%s %s', d.s, d.device_token?'OK':'FAIL', d._err?.message||'');
if(!d.device_token) process.exit(1);
seedCookies(d.cookies||{});
const r = await passportCall(dev, d, '/passport/user/check_email_registered', { params:{ account_sdk_source:'app', multi_login:'1', email: enc('chk'+crypto.randomBytes(4).toString('hex')+'@gmail.com'), mix_mode:'1' } });
const ec = r.j?.data?.error_code ?? r.j?.message;
console.log('[check_email GOC] http=%s ec=%s desc=%s', r.status, ec, (r.j?.data?.description||r.j?.message||'').slice(0,45));
console.log(ec==='success'||r.j?.message==='success'||ec===1011 ? '✅ identity GỐC CÒN TRUSTED — trust bám openudid gốc 8f6453, rotation của tôi tạo mismatch. FIX: ký bằng identity gốc!' : ec===1105 ? '⚠️ vẫn captcha — trust hạ cả identity gốc' : '? ec='+ec);
