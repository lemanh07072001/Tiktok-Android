import { dsign } from '../src/device.mjs';
import { passportCall, enc, seedCookies } from '../src/login.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
const s = JSON.parse(fs.readFileSync('ground-truth/untrusted_devreg.json','utf8'));
const forge = { device_id: s.device_id, install_id: s.resp?.install_id_str||s.resp?.install_id, id: s.id };
const trusted = { device_id:'7664922900961740308', install_id:'7664924131670378260',
  id:{ openudid:'8f6453d9327f0db3', cdid:'60c008e3-6bef-418d-beda-bffca20321c8', clientudid:'bee6562e-ac0b-4eb5-bc56-25bd5a9602cd', google_aid:'5542723c-a932-41db-87d3-1aaa3aba7a99' } };
for (const [name,dev] of [['FORGE 7664928',forge],['TRUSTED 7664922',trusted]]){
  try {
    const d = await dsign(dev); seedCookies(d.cookies||{});
    const r = await passportCall(dev, d, '/passport/user/check_email_registered', { params:{ account_sdk_source:'app', multi_login:'1', email: enc('chk'+crypto.randomBytes(4).toString('hex')+'@gmail.com'), mix_mode:'1' } });
    const ec = r.j?.data?.error_code ?? r.j?.message;
    console.log('%s → check_email http=%s ec=%s desc=%s', name, r.status, ec, (r.j?.data?.description||r.j?.message||'').slice(0,40));
  } catch(e){ console.log('%s ERR %s', name, e.message); }
}
