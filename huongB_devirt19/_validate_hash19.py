#!/usr/bin/env python3
# Validate #19 formula against genuine decoded reports (pas_2/pas_3).
import re
from xargus_decode import decode_xargus
from sm3_hash19 import build_query, report_pskcalhash_19, HASH19_PARAM_ORDER

D = r'E:\tiktok_signer\mobile\frida\out\passport'


def get_url_params(txt):
    line0 = txt.splitlines()[0]
    m = re.search(r'https?://\S+', line0) or re.search(r'https?://\S+', txt)
    url = m.group(0)
    qs = url.split('?', 1)[1]
    params = {}
    for kv in qs.split('&'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            params[k] = v
    return params, url


for n in (2, 3):
    txt = open(D + rf'\pas_{n}_req.txt', encoding='utf-8', errors='ignore').read()
    params, url = get_url_params(txt)
    rep = decode_xargus(re.search(r'x-argus:\s*([A-Za-z0-9+/=]+)', txt, re.I).group(1)).hex()
    i19 = rep.find('9a0120')
    real19 = rep[i19 + 6:i19 + 6 + 64]

    q = build_query(params)
    present = [k for k in HASH19_PARAM_ORDER if k in params]
    missing = [k for k in HASH19_PARAM_ORDER if k not in params]

    calc_zero = report_pskcalhash_19(q).hex()
    print(f'pas_{n}: {len(present)}/39 order-keys present; missing={missing}')
    print(f'   query = {q.decode("latin1")[:110]}...')
    print(f'   real #19 = {real19}')
    print(f'   calc #19 = {calc_zero}  (slot16=zero)')
    print(f'   MATCH(zero slot16) = {calc_zero == real19}')
    print()
