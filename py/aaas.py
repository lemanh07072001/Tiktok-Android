"""re/py/aaas.py — aaas verify EMAIL flow (port re/src/aaas.mjs).
challenge_type=2 (EMAIL), action=3 (send) / action=4 (verify). Bám ground-truth mitm + JSB-hook.
Webview JS KHÔNG ký — chỉ gọi native x.request → ta thay bằng metasec. Cookie strip 5-key, referer webview.
"""
import json
import hashlib
import secrets

from errors import StepError, AAAS
from signer import sign_metasec, UA
from device import guards
import net
from net import qs, body_text, now_ms, now_s
from login import pass_query, PHOST, enc, JAR, cookie_hdr, _grab

# cookie strip cho aaas (ground-truth chỉ giữ mấy cái này, KHÔNG sessionid/csrf)
_STRIP = ['store-idc', 'tt-target-idc', 'odin_tt', 'd_ticket', 'msToken']


def _cookie_stripped():
    return '; '.join(f'{k}={JAR[k]}' for k in _STRIP if JAR.get(k) is not None)


# header idv_core webview-referer (ground-truth authenticate). pba/oec theo 45.0.3 signer.
_REF = {
    'x-tt-referer': 'https://inapp.tiktokv.com/ucenter_web/idv_core/verification',
    'x-bd-kmsv': '0', 'x-tt-pba-encode': '0000',
    'oec-cs-si-a': '2', 'oec-cs-sdk-version': 'v10.02.06-ov-android_V31', 'oec-vc-sdk-version': '3.2.1.i18n',
    'x-vc-bdturing-sdk-version': '2.4.2.i18n', 'x-tt-request-tag': 'n=0;nr=011;bg=0;s=-1;p=0',
    'rpc-persist-pns-region-1': 'VN|1562822|1581129', 'rpc-persist-pns-region-2': 'VN|1562822|1581129',
    'rpc-persist-pns-region-3': 'VN|1562822|1581129',
}


def new_pseudo_id():
    alpha = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return 'PID' + ''.join(alpha[secrets.randbelow(36)] for _ in range(16))


def _auth_post(dev, d, params, tt_token='', step='authenticate'):
    """POST authenticate — params vào CẢ query lẫn body, cookie strip, referer webview, sign metasec."""
    api_path = '/passport/aaas/authenticate/'
    nms, ns = now_ms(), now_s()
    body = qs({k: str(v) for k, v in params.items()})
    q = pass_query(dev)
    q['_rticket'] = str(nms)
    q['ts'] = str(ns)
    for k, v in params.items():
        q[k] = str(v)   # inQuery
    q['request_tag_from'] = 'h5'
    url = f'https://{PHOST}{api_path}?' + qs(q)
    stub = hashlib.md5(body.encode('utf-8')).hexdigest().upper()
    ck = _cookie_stripped()
    g = guards(d, api_path, ns, ticket=tt_token)   # ticket = x-tt-token (rỗng theo ground-truth)
    blk = '\r\n'.join(['x-ss-stub', stub, 'content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
                       'x-ss-req-ticket', str(nms), 'x-tt-token', tt_token or '', 'cookie', ck,
                       'user-agent', UA, 'sdk-version', '2', 'passport-sdk-version', '1'])
    sig = sign_metasec(url, blk, ns, step=step)
    headers = {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-stub': stub,
        'x-ss-req-ticket': str(nms), 'sdk-version': '2', 'passport-sdk-version': '1',
        'accept': 'application/json, text/plain, */*', 'x-tt-dm-status': 'login=0;ct=0;rt=7',
        'x-tt-bypass-dp': '1', 'cookie': ck, 'user-agent': UA, 'accept-encoding': 'gzip', **_REF, **g, **sig,
    }
    if tt_token:
        headers['x-tt-token'] = tt_token
    resp = net.http('POST', url, headers=headers, data=body.encode('utf-8'),
                    step=step, endpoint=api_path, layer=AAAS)
    _grab(resp)
    txt = body_text(resp)
    j = None
    try:
        j = json.loads(txt)
    except Exception:
        pass
    ec = (j.get('data') or {}).get('error_code', j.get('message')) if j else None
    return {'status': resp.status_code, 'txt': txt, 'j': j, 'ec': ec,
            'd_ticket': resp.headers.get('d_ticket') or ''}


def _aaas_get(dev, d, api_path, extra_query=None, tt_token='', step='aaas_get'):
    nms, ns = now_ms(), now_s()
    q = pass_query(dev)
    q['_rticket'] = str(nms)
    q['ts'] = str(ns)
    for k, v in (extra_query or {}).items():
        q[k] = str(v)
    url = f'https://{PHOST}{api_path}?' + qs(q)
    ck = cookie_hdr()
    g = guards(d, api_path, ns, ticket=tt_token)
    blk = '\r\n'.join(['content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
                       'x-ss-req-ticket', str(nms), 'x-tt-token', tt_token or '', 'cookie', ck,
                       'user-agent', UA, 'sdk-version', '2', 'passport-sdk-version', '1'])
    sig = sign_metasec(url, blk, ns, step=step)
    headers = {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-ss-req-ticket': str(nms),
        'sdk-version': '2', 'passport-sdk-version': '1', 'accept': 'application/json, text/plain, */*',
        'cookie': ck, 'user-agent': UA, 'accept-encoding': 'gzip', **_REF, **g, **sig,
    }
    if tt_token:
        headers['x-tt-token'] = tt_token
    resp = net.http('GET', url, headers=headers, step=step, endpoint=api_path, layer=AAAS)
    _grab(resp)
    txt = body_text(resp)
    j = None
    try:
        j = json.loads(txt)
    except Exception:
        pass
    ec = (j.get('data') or {}).get('error_code', j.get('message')) if j else None
    return {'status': resp.status_code, 'txt': txt, 'j': j, 'ec': ec}


def challenges(dev, d, ticket, tt_token=''):
    """challenges → factors ([{type:2}] = email)."""
    return _aaas_get(dev, d, '/passport/aaas/challenges/', step='challenges',
                     extra_query={'request_tag_from': 'h5', 'skip_handler': 'error_handler',
                                  'passport_ticket': ticket}, tt_token=tt_token)


def auth_send(dev, d, ticket, pid, tt_token=''):
    """action=3 SEND code tới email."""
    return _auth_post(dev, d, {'mix_mode': '0', 'pseudo_id': pid, 'challenge_type': '2', 'action': '3',
                               'passport_ticket': ticket, 'skip_handler': 'error_handler',
                               'fixed_mix_mode': '0'}, tt_token=tt_token, step='auth_send')


def auth_verify(dev, d, ticket, pid, code, tt_token=''):
    """action=4 VERIFY code=enc(code)."""
    return _auth_post(dev, d, {'mix_mode': '1', 'code': enc(code), 'pseudo_id': pid, 'challenge_type': '2',
                               'action': '4', 'passport_ticket': ticket, 'skip_handler': 'error_handler',
                               'fixed_mix_mode': '1'}, tt_token=tt_token, step='auth_verify')
