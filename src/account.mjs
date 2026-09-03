import crypto from 'node:crypto';
import { signOffline } from '../../mobile/sign.mjs';
import './net.mjs';
import { passQuery } from './login.mjs';

const PHOST = 'api16-normal-c-alisg.tiktokv.com';

function genEmail() {
  const rand = crypto.randomBytes(6).toString('hex');
  return `re_${rand}@gmail.com`;
}

function enc(s) {
  return Buffer.from(s).toString('utf8').split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x05)).join('');
}

async function checkEmailRegistered(dev, d, email) {
  const ts = Math.floor(Date.now() / 1000);
  const path = '/passport/user/check_email_registered/';
  const qs = passQuery(dev);
  qs.set('email', enc(email));
  qs.set('account_sdk_source', 'app');
  qs.set('multi_login', '1');
  qs.set('mix_mode', '1');
  const body = `account_sdk_source=app&multi_login=1&email=${enc(email)}&mix_mode=1`;
  const stub = crypto.createHash('md5').update(body).digest('hex').toUpperCase();
  const nowMs = Date.now();
  const headerBlockStr = `x-ss-stub\r\n${stub}\r\ncontent-type\r\napplication/x-www-form-urlencoded; charset=UTF-8\r\nx-ss-req-ticket\r\n${nowMs}\r\ncookie\r\nstore-idc=alisg`;
  const signed = await signOffline(`https://${PHOST}${path}?${qs}`, headerBlockStr, ts);
  const headers = {
    'x-ss-stub': stub,
    'x-ss-req-ticket': String(nowMs),
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'cookie': 'store-idc=alisg',
    ...signed
  };
  const url = `https://${PHOST}${path}?${qs}`;
  const r = await fetch(url, { method: 'POST', headers, body });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch {}
  return { status: r.status, j, ec: j?.data?.error_code, txt };
}

async function sendVerifyCode(dev, d, email, captchaToken = '') {
  const ts = Math.floor(Date.now() / 1000);
  const path = '/passport/email/send_code/';
  const qs = passQuery(dev);
  qs.set('mix_mode', '1');
  const bodyParams = { email: enc(email), mix_mode: '1', account_sdk_source: 'app', type: '8' };
  if (captchaToken) bodyParams['cap_data'] = captchaToken;
  const body = new URLSearchParams(bodyParams).toString();
  const stub = crypto.createHash('md5').update(body).digest('hex').toUpperCase();
  const nowMs = Date.now();
  const headerBlockStr = `x-ss-stub\r\n${stub}\r\ncontent-type\r\napplication/x-www-form-urlencoded; charset=UTF-8\r\nx-ss-req-ticket\r\n${nowMs}\r\ncookie\r\nstore-idc=alisg`;
  const signed = await signOffline(`https://${PHOST}${path}?${qs}`, headerBlockStr, ts);
  const headers = {
    'x-ss-stub': stub,
    'x-ss-req-ticket': String(nowMs),
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'cookie': 'store-idc=alisg',
    ...signed
  };
  const url = `https://${PHOST}${path}?${qs}`;
  const r = await fetch(url, { method: 'POST', headers, body });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch {}
  return { status: r.status, j, ec: j?.data?.error_code, txt };
}

async function registerVerifyLogin(dev, d, email, password, verifyCode, birthday = '2000-01-01') {
  const ts = Math.floor(Date.now() / 1000);
  const path = '/passport/email/register_verify_login/';
  const qs = passQuery(dev);
  qs.set('mix_mode', '1');
  qs.set('fixed_mix_mode', '1');
  const bodyParams = {
    birthday: birthday,
    fixed_mix_mode: '1',
    code: enc(verifyCode),
    password: enc(password),
    account_sdk_source: 'app',
    mix_mode: '1',
    multi_login: '1',
    type: '8',
    email: enc(email),
  };
  const body = new URLSearchParams(bodyParams).toString();
  const stub = crypto.createHash('md5').update(body).digest('hex').toUpperCase();
  const nowMs = Date.now();
  const headerBlockStr = `x-ss-stub\r\n${stub}\r\ncontent-type\r\napplication/x-www-form-urlencoded; charset=UTF-8\r\nx-ss-req-ticket\r\n${nowMs}\r\ncookie\r\nstore-idc=alisg`;
  const signed = await signOffline(`https://${PHOST}${path}?${qs}`, headerBlockStr, ts);
  const headers = {
    'x-ss-stub': stub,
    'x-ss-req-ticket': String(nowMs),
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'cookie': 'store-idc=alisg',
    ...signed
  };
  const url = `https://${PHOST}${path}?${qs}`;
  const r = await fetch(url, { method: 'POST', headers, body });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch {}
  return { status: r.status, j, ec: j?.data?.error_code, txt };
}

export { genEmail, checkEmailRegistered, sendVerifyCode, registerVerifyLogin };
