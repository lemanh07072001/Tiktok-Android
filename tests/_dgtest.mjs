import crypto from 'node:crypto';
import { setGlobalDispatcher, ProxyAgent } from 'undici';
import { dsign } from '../src/device.mjs';
setGlobalDispatcher(new ProxyAgent({ uri: process.env.PROXY, connect:{timeout:15000}, headersTimeout:30000, bodyTimeout:30000 }));
const dev = { device_id:'7674521198550435349', install_id:'7674523412790527764',
  id:{ openudid:'338330350a2a79a2', cdid:'3e233f7c-4f5c-4634-83f8-a4212d13f640', google_aid: crypto.randomUUID() },
  openudid:'338330350a2a79a2', cdid:'3e233f7c-4f5c-4634-83f8-a4212d13f640' };
const KEY = '658db77a259041658cf8237065d76d5f5734a3526bfe54ac6befe3bf6fcf07ca';
try {
  const d = await dsign(dev, KEY);
  console.log('DSIGN(genuine key) → s=', d.s, '| ts_sign=', (d.ts_sign||'(RỖNG)').slice(0,30), '| device_token=', (d.device_token||'').slice(0,50));
} catch(e){ console.log('dsign err:', e.message); }
