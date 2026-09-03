import '../src/net.mjs';
import { dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';
const dev = { device_id:'7664922900961740308', install_id:'7664924131670378260',
  openudid:'bb47131b77ddc5ba', cdid:'c3d639a8-3257-44f6-a5b3-63e37298eaf3',
  id:{ openudid:'bb47131b77ddc5ba', cdid:'c3d639a8-3257-44f6-a5b3-63e37298eaf3', clientudid:'817d5d64-e180-4845-8163-eaa9f8e76b82', google_aid:'9d42f65e-a38f-419b-a641-cf4b0d0be2aa' } };
const d = await dsign(dev).catch(e=>({_err:e}));
console.log('[dsign] s=%s token=%s %s', d.s, d.device_token?'OK':'FAIL', d._err?.message||'');
if(!d.device_token) process.exit(1);
seedCookies(d.cookies||{});
const r = await passportCall(dev, d, '/passport/user/check_email_registered', { params:{ account_sdk_source:'app', multi_login:'1', email: enc('chk'+crypto.randomBytes(4).toString('hex')+'@gmail.com'), mix_mode:'1' } });
const ec = r.j?.data?.error_code ?? r.j?.message;
console.log('[check_email] http=%s ec=%s desc=%s', r.status, ec, (r.j?.data?.description||r.j?.message||'').slice(0,45));
console.log(ec==='success'||r.j?.message==='success'||ec===1011 ? '✅ device 7664922 CÒN TRUSTED (ec=7 login chỉ là rate-limit)' : ec===1105 ? '⚠️ CAPTCHA — trust bị hạ (rotation ảnh hưởng?)' : ec===7?'❌ ec7 — UNTRUSTED (rotation phá trust!)' : '? ec='+ec);
