import { dsign } from '../src/device.mjs';
import fs from 'node:fs';
// forge 7664928
const s = JSON.parse(fs.readFileSync('ground-truth/untrusted_devreg.json','utf8'));
const forge = { device_id: s.device_id, install_id: s.resp?.install_id_str||s.resp?.install_id, id: s.id };
// trusted 7664922 (phone that) — identity full
const trusted = { device_id:'7664922900961740308', install_id:'7664924131670378260',
  id:{ openudid:'8f6453d9327f0db3', cdid:'60c008e3-6bef-418d-beda-bffca20321c8', clientudid:'bee6562e-ac0b-4eb5-bc56-25bd5a9602cd', google_aid:'5542723c-a932-41db-87d3-1aaa3aba7a99' } };
for (const [name,dev] of [['FORGE 7664928',forge],['TRUSTED 7664922',trusted]]){
  try { const d = await dsign(dev); console.log('%s → dsign s=%s token=%s', name, d.s, d.device_token?'OK':'FAIL'); }
  catch(e){ console.log('%s → dsign ERR %s', name, e.message); }
}
