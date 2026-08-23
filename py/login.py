"""re/py/login.py — login chain pre_check → user/login → 2135 (port re/src/login.mjs).
Điểm mấu chốt: genuine_headers (đủ oec-cs/oec-vc/rpc-persist/pba/request-tag) + guards().
Bám ground-truth 02_auth_chain.mitm.json (genuine user/login → 2135).
"""
import os
import json
import base64
import hashlib

from errors import StepError, LOGIN
from signer import metasec_block, sign_metasec, genuine_headers, UA
from device import guards
import net
from net import qs, body_text, grab_cookies, now_ms, now_s
from profiles import P

PHOST = 'api16-normal-c-alisg.tiktokv.com'

# enc = XOR 0x05 → hex (username/password/code/email). dec = nghịch đảo.
def enc(s):
    return ''.join('%02x' % (b ^ 0x05) for b in s.encode('utf-8'))


def dec(h):
    raw = bytes(int(h[i:i + 2], 16) ^ 0x05 for i in range(0, len(h), 2))
    return raw.decode('utf-8')


# version: '45.7.3' (default, spoof khớp genuine) | '45.0.3' (khớp signer).
_V = ({'name': '45.0.3', 'code': '450003', 'mvc': '2024500030'}
      if os.environ.get('RE_VER') == '45.0.3'
      else {'name': '45.7.3', 'code': '450703', 'mvc': '2024507030'})


def pass_query(dev):
    ns = now_s()
    return {
        'passport-sdk-version': '1', 'device_platform': 'android', 'os': 'android', 'ssmix': 'a',
        'channel': 'googleplay', 'aid': '1233', 'app_name': 'musical_ly', 'version_code': _V['code'],
        'version_name': _V['name'], 'manifest_version_code': _V['mvc'], 'update_version_code': _V['mvc'],
        'ab_version': _V['name'], 'resolution': P['res'], 'dpi': str(P['dpi']), 'device_type': P['model'],
        'device_brand': P['brand'], 'language': 'en', 'os_api': str(P['os_api']), 'os_version': P['osv'],
        'ac': 'wifi', 'is_pad': '0', 'app_type': 'normal', 'sys_region': 'US',
        'timezone_name': 'Asia/Ho_Chi_Minh', 'app_language': 'en', 'timezone_offset': '25200',
        'host_abi': 'arm64-v8a', 'locale': 'en', 'region': 'US', 'op_region': 'VN', 'build_number': _V['name'],
        'current_region': 'VN', 'residence': 'VN', 'ac2': 'wifi', 'uoo': '0', 'support_webview': '1',
        'last_install_time': str(ns - 200), 'cronet_version': '41c3dc2f_2026-04-08',
        'ttnet_version': '4.2.243.50-tiktok', 'use_store_region_cookie': '1',
        'device_id': dev['device_id'], 'iid': dev['install_id'],
    }


# ── JAR cookie (thủ công, như .mjs) ──
JAR = {'store-idc': 'alisg', 'tt-target-idc': 'alisg'}
if os.environ.get('RE_MSTOKEN'):
    JAR['msToken'] = os.environ['RE_MSTOKEN']
_STRIP5 = ['store-idc', 'tt-target-idc', 'odin_tt', 'd_ticket', 'msToken']


def cookie_hdr():
    return '; '.join(f'{k}={v}' for k, v in JAR.items())


def cookie_stripped():
    return '; '.join(f'{k}={JAR[k]}' for k in _STRIP5 if JAR.get(k) is not None)


def seed_cookies(obj):
    """seed cookie từ register/dsign (odin_tt device cookie) vào JAR."""
    JAR.update(obj or {})


def _grab(resp):
    for k, v in grab_cookies(resp).items():
        JAR[k] = v


def build_call(dev, d, api_path, method='POST', params=None, extra_query=None, tt_token='',
               extra=None, strip_cookie=False, host=None, keep_tg=False, drop_dg=False,
               cookie_override=None):
    """Dựng {url, method, headers, body} — KHÔNG gửi (dùng cho diff/relogin/write-op).
    host: override PHOST (vd aweme api22). keep_tg: GIỮ tt-ticket-guard-client-data (write-op follow/digg).
    drop_dg: BỎ device-guard (aweme write-op genuine KHÔNG gửi). cookie_override: cookie tùy chỉnh (session)."""
    params = params or {}
    nms, ns = now_ms(), now_s()
    body = qs({k: str(v) for k, v in params.items()}) if method == 'POST' else ''
    q = pass_query(dev)
    q['_rticket'] = str(nms)
    q['ts'] = str(ns)
    for k, v in (extra_query or {}).items():
        q[k] = str(v)
    url = f'https://{host or PHOST}{api_path}?' + qs(q)
    if cookie_override is not None:
        cookie = cookie_override
    else:
        cookie = cookie_stripped() if strip_cookie else cookie_hdr()
    stub = hashlib.md5(body.encode('utf-8')).hexdigest().upper() if body else None
    block = metasec_block(stub=stub, req_ticket=nms, tt_token=tt_token, cookie=cookie)
    sig = sign_metasec(url, block, ns, step='passport_call')
    g = guards(d, api_path, ns, ticket=tt_token)
    if not keep_tg:
        g.pop('tt-ticket-guard-client-data', None)   # genuine user/login KHÔNG gửi; write-op thì CẦN
    if drop_dg:                                        # aweme write-op genuine KHÔNG gửi device-guard
        g.pop('tt-device-guard-client-data', None)
        g.pop('tt-device-guard-iteration-version', None)
    headers = genuine_headers(body=body, req_ticket_ms=nms, tt_token=tt_token, cookie=cookie,
                              extra={**g, **sig, **(extra or {})})
    return {'url': url, 'method': method, 'headers': headers, 'body': body, 'endpoint': api_path}


def passport_call(dev, d, api_path, method='POST', params=None, extra_query=None, tt_token='',
                  extra=None, strip_cookie=False, step=None, host=None, keep_tg=False, drop_dg=False,
                  cookie_override=None, layer=LOGIN):
    """1 passport call — FULL genuine headers + guards + metasec. Xem build_call cho host/keep_tg/drop_dg."""
    step = step or api_path
    c = build_call(dev, d, api_path, method=method, params=params, extra_query=extra_query,
                   tt_token=tt_token, extra=extra, strip_cookie=strip_cookie, host=host,
                   keep_tg=keep_tg, drop_dg=drop_dg, cookie_override=cookie_override)
    resp = net.http(c['method'], c['url'], headers=c['headers'],
                    data=c['body'].encode('utf-8') if c['method'] == 'POST' else None,
                    step=step, endpoint=api_path, layer=layer)
    _grab(resp)
    # ⭐ LIVE ts_sign: server cấp tt-ticket-guard-server-data (per-session) → cập nhật d['ts_sign'] cho write-op.
    try:
        sd = resp.headers.get('tt-ticket-guard-server-data') or resp.headers.get('Tt-Ticket-Guard-Server-Data')
        if sd:
            ts = json.loads(base64.b64decode(sd).decode('utf-8')).get('ts_sign')
            if ts:
                d['ts_sign'] = ts
    except Exception:
        pass
    txt = body_text(resp)
    j = None
    try:
        j = json.loads(txt)
    except Exception:
        pass
    # 2135: ticket + pseudo_id ở HEADER x-tt-verify-idv-decision-conf (note 19/26), KHÔNG ở body
    dc = None
    try:
        h = resp.headers.get('x-tt-verify-idv-decision-conf')
        if h:
            dc = json.loads(h)
    except Exception:
        pass
    ec = None
    if j:
        ec = (j.get('data') or {}).get('error_code', j.get('message'))
    return {
        'status': resp.status_code, 'txt': txt, 'j': j, 'ec': ec,
        'xtt': resp.headers.get('x-tt-token') or '',
        'd_ticket': resp.headers.get('d_ticket') or '',
        'dc': dc, 'endpoint': api_path,
    }


# ── warmup pre-login (lập cookie odin_tt + device session) ──
def store_region(dev, d):
    return passport_call(dev, d, '/passport/app/store_region/', params={'store_region_src': 'uid'},
                         step='store_region')


def get_nonce(dev, d):
    return passport_call(dev, d, '/passport/auth/get_nonce/', params={'platform': 'google'}, step='get_nonce')


def app_region(dev, d):
    hid = hashlib.sha256(dev['device_id'].encode('utf-8')).hexdigest()
    return passport_call(dev, d, '/passport/app/region/', params={'type': '2', 'hashed_id': hid},
                         step='app_region')


def warmup(dev, d):
    for fn in (store_region, get_nonce, app_region):
        try:
            fn(dev, d)
        except StepError:
            pass   # best-effort, không chặn chain
    return list(JAR.keys())


# ── pre_check → login_page ──
def pre_check(username, dev, d):
    return passport_call(dev, d, '/passport/user/login/pre_check/', step='pre_check',
                         params={'account_sdk_source': 'app', 'multi_login': '1', 'mix_mode': '1',
                                 'username': enc(username)})


# ── user/login → 2135 (+aaas_ticket) hoặc ec7 ──
def user_login(username, password, dev, d):
    return passport_call(dev, d, '/passport/user/login/', step='user_login',
                         params={'password': enc(password), 'account_sdk_source': 'app',
                                 'multi_login': '1', 'mix_mode': '1', 'username': enc(username)})
