# survey_body.py — soi encoding body mọi request auth (verify enc).
import json, re
auth = json.load(open('../ground-truth/02_auth_chain.mitm.json', encoding='utf-8'))
frida = [json.loads(l) for l in open('../../mobile/frida/out/api_capture/_all.jsonl', encoding='utf-8') if l.strip()]

def fmt(body):
    if not body: return 'RONG'
    b = body.strip()
    if b.startswith('{'): return 'JSON plaintext'
    if re.match(r'^\w+=', b): return 'form-urlencoded'
    if re.match(r'^[0-9a-f]+$', b): return 'hex'
    return 'khac/binary'

def enc_scan(body):
    out = []
    for kv in (body or '').split('&'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            if re.match(r'^[0-9a-f]{6,}$', v) and len(v) % 2 == 0:
                try:
                    dec = ''.join(chr(x ^ 0x05) for x in bytes.fromhex(v))
                    if dec.isprintable(): out.append('%s=enc(%s)' % (k, dec[:22]))
                except Exception: pass
    return out

print('=== POST body passport/aaas (auth chain) ===')
seen = set()
for e in auth:
    if e.get('method') != 'POST': continue
    p = re.sub(r'https?://[^/]+', '', e['url']).split('?')[0]
    if p in seen: continue
    seen.add(p)
    body = e.get('req_body') or ''
    ef = enc_scan(body)
    print('  %-42s [%s]%s' % (p, fmt(body), ('  ENC: ' + ' '.join(ef)) if ef else ''))

print('\n=== device_register / dsign (frida) ===')
for e in frida:
    p = re.sub(r'https?://[^/]+', '', e['url']).split('?')[0]
    if p in ('/service/2/device_register/', '/service/2/dsign/'):
        print('  %-30s [%s]' % (p, fmt(e.get('req_body'))))
