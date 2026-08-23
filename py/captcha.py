"""re/py/captcha.py — GIẢI captcha TikTok (ec1105/1108) headless: /captcha/get → decrypt(ChaCha20) →
   omocaptcha (slide) / self-solve (hashcash) → /captcha/verify. Port mobile/captcha_api_solve.mjs.
  Cần OMO_API_KEY (omocaptcha) cho SLIDE; HASHCASH tự giải (không cần key). Gọi solve_captcha(dev)
  khi login gặp 1105/1108, rồi RETRY request. Ký /captcha/* qua signer bridge; đi qua PROXY (net.http).
"""
import os
import json
import time
import hashlib

import requests

from errors import SESSION
from signer import sign_metasec, UA
import net
from net import qs, body_text, now_ms, now_s
import edata

VHOST = 'rc-verification-sg.tiktokv.com'
OMO_BASE = 'https://api.omocaptcha.com/v2'
BROWSER_UA = ('Mozilla/5.0 (Linux; Android 9; SM-G930F Build/PQ3A.190801.002; wv) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 '
              'musical_ly_2024500030 JsSdk/1.0 NetType/WIFI Channel/googleplay AppName/musical_ly '
              'app_version/45.0.3 ByteLocale/en ByteFullLocale/en Region/VN AppId/1233 Spark/1.7.2 '
              'AppVersion/45.0.3 PIA/2.5.3 BytedanceWebview/d8a21c6')


def captcha_common_q(dev, extra=None):
    q = {
        'lang': 'en', 'app_name': 'musical_ly', 'h5_sdk_version': '2.34.12', 'sdk_version': '2.4.2.i18n',
        'iid': dev['install_id'], 'did': dev['device_id'], 'device_id': dev['device_id'], 'ch': 'googleplay',
        'aid': '1233', 'os_type': '0', 'mode': 'unset', 'tmp': str(now_ms()), 'platform': 'app',
        'webdriver': 'undefined', 'enable_image': '1', 'verify_host': 'https://' + VHOST + '/', 'locale': 'en',
        'channel': 'googleplay', 'app_key': '', 'vc': '45.0.3', 'app_version': '45.0.3', 'session_id': '',
        'region': 'sg', 'userMode': '257', 'use_native_report': '1', 'use_jsb_request': '1', 'orientation': '2',
        'resolution': '1440*2392', 'os_version': '28', 'device_brand': 'samsung', 'device_model': 'SM-G930F',
        'os_name': 'Android', 'version_code': '4503', 'device_type': 'SM-G930F', 'device_platform': 'Android',
        'store_region': 'vn', 'imagex_domain': '', 'subtype': '', 'challenge_code': '99999',
        'triggered_region': 'sg', 'cookie_enabled': 'true', 'screen_width': '412', 'screen_height': '732',
        'browser_language': 'en', 'browser_platform': 'Linux armv8l', 'browser_name': 'Mozilla',
        'browser_version': BROWSER_UA, 'mobile_container': 'spark',
    }
    if extra:
        q.update({k: str(v) for k, v in extra.items()})
    return qs(q)


def _block(stub, nms):
    parts = (['x-ss-stub', stub] if stub else []) + [
        'content-type', 'application/json; charset=utf-8', 'x-ss-req-ticket', str(nms),
        'x-tt-token', '', 'cookie', 'store-idc=alisg', 'user-agent', UA,
        'sdk-version', '2', 'passport-sdk-version', '1']
    return '\r\n'.join(parts)


def captcha_req(method, path, query, body=None):
    ns, nms = now_s(), now_ms()
    url = 'https://' + VHOST + path + '?' + query
    stub = None
    if body:
        bb = body.encode('utf-8') if isinstance(body, str) else body
        stub = hashlib.md5(bb).hexdigest().upper()
    sig = sign_metasec(url, _block(stub, nms), ns, step='captcha')
    headers = {'content-type': 'application/json; charset=utf-8', 'x-tt-token': '', 'cookie': 'store-idc=alisg',
               'user-agent': UA, 'sdk-version': '2', 'passport-sdk-version': '1',
               'accept-encoding': 'gzip', **sig}
    if stub:
        headers['x-ss-stub'] = stub
        headers['x-ss-req-ticket'] = str(nms)
    data = (body.encode('utf-8') if isinstance(body, str) else body) if body else None
    resp = net.http(method, url, headers=headers, data=data, step='captcha', endpoint=path, layer=SESSION)
    return {'status': resp.status_code, 'body': body_text(resp)}


def omo_solve(img_bytes):
    """omocaptcha TiktokSliderWebTask → end.x (348-space = distance). None nếu lỗi/không key."""
    key = os.environ.get('OMO_API_KEY')
    if not key:
        return None
    import base64
    try:
        c = requests.post(OMO_BASE + '/createTask', timeout=30, json={
            'clientKey': key, 'task': {'type': 'TiktokSliderWebTask',
                                       'imageBase64': base64.b64encode(img_bytes).decode(),
                                       'widthView': edata.DRAGW}}).json()
        tid = c.get('taskId')
        if not tid:
            return None
        for _ in range(12):
            time.sleep(2.5)
            r = requests.post(OMO_BASE + '/getTaskResult', timeout=30,
                              json={'clientKey': key, 'taskId': tid}).json()
            if r.get('status') == 'ready':
                return ((r.get('solution') or {}).get('end') or {}).get('x')
            if r.get('errorId'):
                return None
    except Exception:
        return None
    return None


def solve_captcha(dev, d=None, max_tries=10, log=None):
    """Giải captcha cho device đang ở 1105/1108. Retry tới khi code 200. Trả {ok, tries}."""
    for t in range(1, max_tries + 1):
        try:
            g = captcha_req('GET', '/captcha/get', captcha_common_q(dev))
            challenge = edata.decrypt_edata(json.loads(g['body'])['edata'])
        except Exception:
            continue
        chs = (challenge.get('data') or {}).get('challenges') or []
        if not chs:
            continue
        ch = chs[0]
        mode = ch.get('mode')
        if mode == 'hashcash':
            ans = edata.answer_hashcash(challenge)
            sub = {'mode': 'hashcash', 'subtype': 'hashcash'}
        elif mode == 'slide':
            try:
                img = requests.get(ch['question']['url1'], timeout=20).content
            except Exception:
                continue
            endx = omo_solve(img)
            if endx is None:
                if log:
                    log(f'  captcha try#{t}: omocaptcha lỗi/không OMO_API_KEY')
                continue
            ans = edata.answer_slide(challenge, round(endx))
            sub = {'mode': 'slide', 'subtype': 'slide'}
        else:
            if log:
                log(f'  captcha try#{t}: mode={mode} chưa hỗ trợ')
            continue
        vq = captcha_common_q(dev, {**sub, 'verify_id': challenge['data']['verify_id'],
                                    'challenge_code': str(ch['challenge_code'])})
        vres = captcha_req('POST', '/captcha/verify', vq, json.dumps({'edata': ans}))
        try:
            vr = edata.decrypt_edata(json.loads(vres['body'])['edata'])
        except Exception:
            vr = {}
        code = vr.get('code') if isinstance(vr, dict) else None
        if log:
            log(f'  captcha try#{t}: {mode} → code={code}')
        if code == 200 or 'success' in json.dumps(vr).lower():
            return {'ok': True, 'tries': t}
    return {'ok': False, 'tries': max_tries}
