"""re/py/signer.py — Signing layer (port re/src/sign.mjs).
Metasec 4-header (X-Argus/Gorgon/Ladon/Khronos) qua CẦU HTTP /sign — Python không tự ký native .so.
  SIGNER_URL (hoặc METASEC_ORACLE) = http://host:port  → POST /sign {url, hdr, headerBlock, khronos}
    - offline unidbg : mobile/server/server.mjs  (:8799)  → {X-Gorgon,X-Khronos,X-Ladon,X-Argus}
    - genuine phone  : oracle                     (:8795)  → {X-Argus,...} (app-grade 728b)
Signer là LOCAL → gọi requests THẲNG, KHÔNG qua proxy egress (giống DIRECT dispatcher .mjs).
"""
import os
import time
import hashlib
import secrets

import requests

from errors import StepError, SIGN
from profiles import make_ua

# ── version ──
RE_VER = os.environ.get('RE_VER')
APP_VC = '2024507030' if RE_VER == '45.7.3' else '2024500030'
UA = make_ua(APP_VC)
_V45 = RE_VER == '45.7.3'

# ── hằng số client-genuine (ground-truth 45.7.3 / 45.0.3) ──
CLIENT_GENUINE = {
    'oec-cs-sdk-version': 'v10.02.09-ov-android_V31' if _V45 else 'v10.02.06-ov-android_V31',
    'oec-cs-si-a': '2',
    'oec-vc-sdk-version': '3.2.3.i18n' if _V45 else '3.2.1.i18n',
    'rpc-persist-pns-region-1': 'VN|1562822|1581129',
    'rpc-persist-pns-region-2': 'VN|1562822|1581129',
    'rpc-persist-pns-region-3': 'VN|1562822|1581129',
    'x-vc-bdturing-sdk-version': '2.4.2.i18n',
    'x-bd-kmsv': '0',
    'x-tt-bypass-dp': '1',
    'x-tt-pba-encode': '0020' if _V45 else '4000',
    'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0',
    'passport-sdk-settings': 'x-tt-token',
    'passport-sdk-sign': 'x-tt-token',
    'passport-sdk-version': '1',
    'sdk-version': '2',
}

SIGNER_URL = (os.environ.get('SIGNER_URL') or os.environ.get('METASEC_ORACLE') or '').rstrip('/')


def md5_stub(body):
    """x-ss-stub = md5(body).hex.upper() ; None nếu body rỗng."""
    if not body:
        return None
    if isinstance(body, str):
        body = body.encode('utf-8')
    return hashlib.md5(body).hexdigest().upper()


def metasec_block(stub=None, req_ticket=None, tt_token='', cookie='', ua=UA):
    """Header BLOCK (\\r\\n key \\r\\n value) làm INPUT cho metasec — đúng thứ tự signer kỳ vọng."""
    parts = []
    if stub:
        parts += ['x-ss-stub', stub]
    parts += ['content-type', 'application/x-www-form-urlencoded; charset=UTF-8']
    parts += ['x-ss-req-ticket', str(req_ticket)]
    parts += ['x-tt-token', tt_token or '']
    parts += ['cookie', cookie or '']
    parts += ['user-agent', ua]
    parts += ['sdk-version', '2', 'passport-sdk-version', '1']
    return '\r\n'.join(parts)


def sign_metasec(url, block, khronos_sec=None, step='sign_metasec'):
    """Ký metasec 4-header. Trả {X-Gorgon,X-Khronos,X-Ladon,X-Argus}. Time-bound (khronos=giây)."""
    if not SIGNER_URL:
        raise StepError(step, SIGN,
                        hint='SIGNER_URL/METASEC_ORACLE chưa set — Python không tự ký metasec. '
                             'Chạy mobile/server/server.mjs (:8799) hoặc phone-oracle rồi export SIGNER_URL.')
    khronos_sec = khronos_sec or int(time.time())
    payload = {'url': url, 'hdr': block, 'headerBlock': block, 'khronos': khronos_sec}
    try:
        r = requests.post(SIGNER_URL + '/sign', json=payload, timeout=30)  # LOCAL — không qua proxy
    except Exception as e:
        raise StepError(step, SIGN, endpoint=SIGNER_URL + '/sign',
                        hint='Không gọi được signer server. Check server chạy + SIGNER_URL đúng.', cause=e)
    try:
        j = r.json()
    except Exception as e:
        raise StepError(step, SIGN, endpoint=SIGNER_URL + '/sign', http=r.status_code,
                        server_msg=r.text[:200], hint='signer trả non-JSON.', cause=e)
    if not j.get('X-Argus'):
        raise StepError(step, SIGN, endpoint=SIGNER_URL + '/sign', http=r.status_code, raw=j,
                        hint='signer không trả X-Argus — signer hỏng/khác version, hoặc oracle mất phone.')
    return {
        'X-Gorgon': j.get('X-Gorgon'),
        'X-Khronos': j.get('X-Khronos') or str(khronos_sec),
        'X-Ladon': j.get('X-Ladon'),
        'X-Argus': j['X-Argus'],
    }


def _trace_id():
    return '00-' + secrets.token_hex(16) + '-' + secrets.token_hex(8) + '-01'


def genuine_headers(body='', req_ticket_ms=None, tt_token='', cookie='', extra=None, dg=None, tg=None):
    """FULL header genuine cho 1 passport request (bám genuine user/login)."""
    stub = md5_stub(body)
    h = {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-ss-req-ticket': str(req_ticket_ms),
        'cookie': cookie,
        'user-agent': UA,
        'accept-encoding': 'gzip, deflate, br',
        'x-tt-trace-id': _trace_id(),
        **CLIENT_GENUINE,
        **(dg or {}),
        **(tg or {}),
        **(extra or {}),
    }
    if tt_token:
        h['x-tt-token'] = tt_token   # genuine BỎ x-tt-token khi rỗng (pre-login)
    if stub:
        h['x-ss-stub'] = stub
    return h
