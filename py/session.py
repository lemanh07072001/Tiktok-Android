"""re/py/session.py — RE-LOGIN #7 (mắt xích cuối, note 26) + xài account bằng session.
relogin: replay user/login BODY byte-identical login gốc + 2 header (x-tt-retry.../x-tt-passport-ticket)
         + cookie strip 5-key (d_ticket inject từ response authenticate #6). Bám note 26.
"""
import json

from errors import StepError, SESSION
from signer import metasec_block, sign_metasec, genuine_headers
from net import qs, body_text, now_ms, now_s
import net
import login
from login import enc, JAR

_SPHOST = 'api22-normal-c-alisg.tiktokv.com'   # api22 clean (read)


def relogin(username, password, dev, d, ticket, d_ticket=''):
    """RE-LOGIN #7: replay user/login → session_key. ticket = aaas passport_ticket, d_ticket từ auth_verify."""
    if d_ticket:
        JAR['d_ticket'] = d_ticket   # inject từ response header authenticate #6 (KHÔNG phải Set-Cookie)
    return login.passport_call(
        dev, d, '/passport/user/login/', step='relogin',
        params={'password': enc(password), 'account_sdk_source': 'app', 'multi_login': '1',
                'mix_mode': '1', 'username': enc(username)},
        extra={'x-tt-retry-by-x-tt-verify-idv-decision-conf': '1', 'x-tt-passport-ticket': ticket},
        strip_cookie=True)


def session_from(lg, dev):
    """Dựng session object từ login SUCCESS (relogin #7)."""
    data = (lg.get('j') or {}).get('data') or {}
    return {
        'cookie': login.cookie_hdr(),
        'device_id': dev['device_id'], 'iid': dev['install_id'],
        'xtt': lg.get('xtt', ''),
        'uid': data.get('user_id_str') or str(data.get('user_id') or ''),
        'session_key': data.get('session_key', ''),
        'sec_uid': data.get('sec_user_id', ''),
        'ts': now_ms(),
    }


def _common_query(device_id, iid):
    return {
        'passport-sdk-version': '1', 'device_platform': 'android', 'os': 'android', 'ssmix': 'a',
        'channel': 'googleplay', 'aid': '1233', 'app_name': 'musical_ly', 'version_code': '450003',
        'version_name': '45.0.3', 'manifest_version_code': '2024500030', 'update_version_code': '2024500030',
        'ab_version': '45.0.3', 'resolution': '1440*2392', 'dpi': '560', 'device_type': 'SM-G930F',
        'device_brand': 'samsung', 'language': 'en', 'os_api': '28', 'os_version': '9', 'ac': 'wifi',
        'is_pad': '0', 'app_type': 'normal', 'sys_region': 'US', 'timezone_name': 'Asia/Ho_Chi_Minh',
        'app_language': 'en', 'timezone_offset': '25200', 'host_abi': 'arm64-v8a', 'locale': 'en',
        'region': 'US', 'op_region': 'VN', 'build_number': '45.0.3', 'current_region': 'VN',
        'residence': 'VN', 'device_id': device_id, 'iid': iid,
    }


def call_authed(session, api_path, extra_query=None, method='GET'):
    """Gọi authenticated bằng session cookie (read không bind device gốc)."""
    cookie = session.get('cookie', '')
    device_id = session.get('device_id', '7661233880557225493')
    iid = session.get('iid', '7661236122685114132')
    xtt = session.get('xtt', '')
    nms, ns = now_ms(), now_s()
    q = _common_query(device_id, iid)
    q['_rticket'] = str(nms)
    q['ts'] = str(ns)
    for k, v in (extra_query or {}).items():
        q[k] = str(v)
    url = f'https://{_SPHOST}{api_path}?' + qs(q)
    block = metasec_block(stub=None, req_ticket=nms, tt_token=xtt, cookie=cookie)
    sig = sign_metasec(url, block, ns, step='call_authed')
    headers = genuine_headers(body='', req_ticket_ms=nms, tt_token=xtt, cookie=cookie, extra=sig)
    resp = net.http(method, url, headers=headers, step='call_authed', endpoint=api_path, layer=SESSION)
    txt = body_text(resp)
    j = None
    try:
        j = json.loads(txt)
    except Exception:
        pass
    return {'status': resp.status_code, 'txt': txt, 'j': j}


def session_from_combo(line):
    """parse combo (field 7 = cookie) → {cookie, uid}."""
    f = line.strip().split('|')
    cookie = (f[7] if len(f) > 7 else '').strip().replace(', ', '; ')
    import re as _re
    m = _re.search(r'multi_sids=(\d+)', cookie)
    return {'cookie': cookie, 'uid': m.group(1) if m else ''}


# ── lưu/nạp session ra file (tái dùng cho write-op mà KHÔNG re-login; tránh tốn quota re-verify) ──
def save_session(sess, dev, d, path):
    """Lưu session + device + EC priv(hex) + guards. Đủ để load_session dựng lại (dev,d) ký write-op."""
    priv_hex = format(d['priv'].private_numbers().private_value, 'x')
    obj = {
        'user': sess.get('user') or sess.get('uid'), 'user_id': sess.get('uid'),
        'sec_uid': sess.get('sec_uid', ''), 'xtt': sess.get('xtt', ''), 'cookie': sess.get('cookie', ''),
        'device': {
            'device_id': dev['device_id'], 'install_id': dev['install_id'],
            'cdid': (dev.get('id') or {}).get('cdid') or dev.get('cdid'),
            'device_token': d['device_token'], 'dtoken_sign': d['dtoken_sign'],
            'ts_sign': d.get('ts_sign', ''), 'ec_priv': priv_hex,
        },
        'ts': now_ms(),
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f)
    return path


def load_session(path):
    """Nạp session file → (dev, d, sess). Rebuild EC priv từ hex → ký được device/ticket-guard."""
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from device import _ec_pub_bytes
    with open(path, encoding='utf-8') as f:
        s = json.load(f)
    dv = s['device']
    priv = _ec.derive_private_key(int(dv['ec_priv'], 16), _ec.SECP256R1())
    dev = {'device_id': dv['device_id'], 'install_id': dv['install_id'],
           'id': {'cdid': dv.get('cdid')}, 'cdid': dv.get('cdid')}
    d = {'device_token': dv['device_token'], 'dtoken_sign': dv['dtoken_sign'],
         'ts_sign': dv.get('ts_sign', ''), 'priv': priv, 'ec_pub': _ec_pub_bytes(priv)}
    return dev, d, s
