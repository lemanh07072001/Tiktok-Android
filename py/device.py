"""re/py/device.py — device_register + device-guard/ticket-guard (port re/src/device.mjs).
Bám ground-truth 01_device_register.frida.json (fingerprint) + guards() proven.
"""
import json
import uuid
import base64
import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from errors import StepError, DEVICE, GUARD
from signer import sign_metasec, UA, md5_stub
import net
from net import SESSION, qs, body_text, grab_cookies, now_ms, now_s
from profiles import P


def md5_upper(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return hashlib.md5(s).hexdigest().upper()


# App musically — 45.0.3 khớp signer unidbg (genuine phone 45.7.3). sig_hash genuine.
APP = {
    'aid': 1233, 'package': 'com.zhiliaoapp.musically', 'app_name': 'musical_ly', 'app_version': '45.0.3',
    'version_code': 2024500030, 'update_version_code': 2024500030, 'manifest_version_code': 2024500030,
    'sig_hash': '194326e82c84a639a52e5c023116f12a', 'ab_version': '45.0.3', 'display_name': 'TikTok',
}


def new_identity():
    return {
        'openudid': secrets.token_hex(8),
        'cdid': str(uuid.uuid4()),
        'clientudid': str(uuid.uuid4()),
        'google_aid': str(uuid.uuid4()),
        'req_id': str(uuid.uuid4()),
    }


def _build_header(idn):
    """FINGERPRINT.header — đa dạng theo profile."""
    h = {
        'os': 'Android', 'os_version': P['osv'], 'os_api': P['os_api'], 'device_model': P['model'],
        'device_brand': P['brand'], 'device_manufacturer': P['mfr'], 'cpu_abi': 'arm64-v8a',
        'density_dpi': P['dpi'], 'display_density': 'mdpi', 'resolution': P['res'].replace('*', 'x'),
        'display_density_v2': 'xxxhdpi', 'resolution_v2': P['resv2'].replace('*', 'x'),
        'access': 'wifi', 'rom': P['rom'], 'rom_version': P['build'], 'language': 'en', 'timezone': 7,
        'tz_name': 'Asia/Ho_Chi_Minh', 'tz_offset': 25200,
        'clientudid': idn['clientudid'], 'openudid': idn['openudid'], 'cdid': idn['cdid'],
        'google_aid': idn['google_aid'], 'req_id': idn['req_id'],
        'device_platform': 'android', 'channel': 'googleplay', 'not_request_sender': 1, 'gaid_limited': 0,
        'guest_mode': 0, 'is_system_app': 0, 'sdk_flavor': 'i18nInner', 'sdk_target_version': 30,
        'sdk_version': '2.5.14.5', 'sdk_version_code': 205140590, 'git_hash': 'b53ca20',
        'release_build': '348bf6c_20260618',
        'custom': {'ram_size': '4GB', 'dark_mode_setting_value': 1, 'is_flip': False},
        'apk_first_install_time': now_ms() - 1000000, 'tweaked_channel': 'googleplay',
    }
    h.update(APP)
    h['device_id'] = '0'
    h['install_id'] = '0'
    return h


def _common_q(idn, nms, ns):
    return {
        'req_id': str(uuid.uuid4()), 'device_platform': 'android', 'os': 'android', 'ssmix': 'a',
        '_rticket': str(nms), 'cdid': idn['cdid'], 'channel': 'googleplay', 'aid': '1233',
        'app_name': 'musical_ly', 'version_code': '2024500030', 'version_name': '45.0.3',
        'manifest_version_code': '2024500030', 'update_version_code': '2024500030', 'ab_version': '45.0.3',
        'resolution': P['res'], 'dpi': str(P['dpi']), 'device_type': P['model'], 'device_brand': P['brand'],
        'language': 'en', 'os_api': str(P['os_api']), 'os_version': P['osv'], 'ac': 'wifi', 'is_pad': '0',
        'app_type': 'normal', 'sys_region': 'US', 'last_install_time': str(ns - 2),
        'timezone_name': 'Asia/Ho_Chi_Minh', 'app_language': 'en', 'timezone_offset': '25200',
        'host_abi': 'arm64-v8a', 'locale': 'en', 'ac2': 'wifi', 'uoo': '1', 'op_region': 'VN',
        'build_number': '45.0.3', 'region': 'US', 'ts': str(ns), 'openudid': idn['openudid'],
        'use_store_region_cookie': '1',
    }


# ── device_register → {device_id, install_id} ──
def register_device(identity=None):
    idn = identity or new_identity()
    nms, ns = now_ms(), now_s()
    body = json.dumps({'header': _build_header(idn), 'magic_tag': 'ss_app_log', '_gen_time': nms},
                      separators=(',', ':'))
    stub = md5_upper(body)
    endpoint = '/service/2/device_register/'
    url = 'https://api-boot.tiktokv.com' + endpoint + '?' + qs(_common_q(idn, nms, ns))
    blk = '\r\n'.join(['x-ss-stub', stub, 'content-type', 'application/json; charset=utf-8',
                       'x-ss-req-ticket', str(nms), 'x-tt-dm-status', 'login=0;ct=0;rt=7',
                       'sdk-version', '2', 'passport-sdk-version', '1', 'user-agent', UA])
    sig = sign_metasec(url, blk, ns, step='register_device')
    headers = {
        'content-type': 'application/json; charset=utf-8', 'x-ss-stub': stub, 'x-ss-req-ticket': str(nms),
        'x-tt-dm-status': 'login=0;ct=0;rt=7', 'sdk-version': '2', 'passport-sdk-version': '1',
        'x-ss-dp': '1233', 'user-agent': UA, 'accept-encoding': 'gzip, deflate, br', **sig,
    }
    resp = net.http('POST', url, headers=headers, data=body.encode('utf-8'),
                    step='register_device', endpoint=endpoint, layer=DEVICE)
    cookies = grab_cookies(resp)
    txt = body_text(resp)
    try:
        j = json.loads(txt)
    except Exception as e:
        raise StepError('register_device', DEVICE, endpoint=endpoint, http=resp.status_code,
                        server_msg=txt[:200], hint='register trả non-JSON — endpoint/format có thể đổi.',
                        cause=e)
    did, iid = j.get('device_id_str'), j.get('install_id_str')
    if not did or not iid:
        raise StepError('register_device', DEVICE, endpoint=endpoint, http=resp.status_code, raw=j)
    return {'device_id': did, 'install_id': iid, 'new_user': j.get('new_user'),
            'id': idn, 'cookies': cookies, 'raw': j}


# ── dsign → device_token (device-guard) + ECDH keypair ──
def _gen_props():
    md5r = lambda: secrets.token_hex(16)
    sha = lambda s: hashlib.sha256(str(s).encode('utf-8')).hexdigest()
    p = {'device_model': P['model'], 'device_manufacturer': P['mfr'], 'resolution': P['res'].replace('*', 'x'),
         'disk_size': sha('disk' + md5r()), 'memory_size': sha('mem' + md5r()), 're_time': md5r()}
    for k in ['indss18', 'indc15', 'indn5', 'indmc14', 'inda0', 'indal2', 'indm10', 'indsp3', 'indsd8',
              'bl', 'cmf', 'bc', 'stz', 'sl']:
        p[k] = md5r()
    return p


def _ec_pub_bytes(priv):
    return priv.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint)  # 65B, prefix 0x04


def dsign(dev, fixed_priv_hex=None):
    nms, ns = now_ms(), now_s()
    idn = dev.get('id') or {}
    openudid = idn.get('openudid') or dev.get('openudid')
    cdid = idn.get('cdid') or dev.get('cdid')
    if fixed_priv_hex:
        priv = ec.derive_private_key(int(fixed_priv_hex, 16), ec.SECP256R1())
    else:
        priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = _ec_pub_bytes(priv)
    body = json.dumps({
        'device_id': dev['device_id'], 'install_id': dev['install_id'], 'aid': 1233, 'app_version': '45.0.3',
        'model': P['model'], 'os': 'Android', 'openudid': openudid,
        'google_aid': idn.get('google_aid') or str(uuid.uuid4()),
        'properties_version': 'android-1.0', 'device_properties': _gen_props(),
    }, separators=(',', ':'))
    stub = md5_upper(body)
    endpoint = '/service/2/dsign/'
    q = {
        'from': 'normal', 'from_error': '', 'device_platform': 'android', 'os': 'android', 'ssmix': 'a',
        '_rticket': str(nms), 'cdid': cdid, 'channel': 'googleplay', 'aid': '1233', 'app_name': 'musical_ly',
        'version_code': '2024500030', 'version_name': '45.0.3', 'manifest_version_code': '2024500030',
        'update_version_code': '2024500030', 'ab_version': '45.0.3', 'resolution': P['res'], 'dpi': str(P['dpi']),
        'device_type': P['model'], 'device_brand': P['brand'], 'language': 'en', 'os_api': str(P['os_api']),
        'os_version': P['osv'], 'ac': 'wifi', 'is_pad': '0', 'app_type': 'normal', 'sys_region': 'US',
        'last_install_time': str(ns - 6), 'timezone_name': 'Asia/Ho_Chi_Minh', 'app_language': 'en',
        'timezone_offset': '25200', 'host_abi': 'arm64-v8a', 'locale': 'en', 'ac2': 'wifi', 'uoo': '0',
        'op_region': 'VN', 'build_number': '45.0.3', 'region': 'US', 'ts': str(ns), 'iid': dev['install_id'],
        'device_id': dev['device_id'], 'openudid': openudid,
    }
    url = 'https://api.tiktokv.com' + endpoint + '?' + qs(q)
    tg_pub = base64.b64encode(ec_pub).decode()
    blk = '\r\n'.join(['x-ss-stub', stub, 'content-type', 'application/json; charset=utf-8',
                       'x-ss-req-ticket', str(nms), 'tt-ticket-guard-public-key', tg_pub,
                       'tt-device-guard-iteration-version', '1', 'sdk-version', '2',
                       'passport-sdk-version', '1', 'user-agent', UA])
    sig = sign_metasec(url, blk, ns, step='dsign')
    headers = {
        'content-type': 'application/json; charset=utf-8', 'x-ss-stub': stub, 'x-ss-req-ticket': str(nms),
        'tt-ticket-guard-public-key': tg_pub, 'tt-device-guard-iteration-version': '1', 'sdk-version': '2',
        'passport-sdk-version': '1', 'x-ss-dp': '1233', 'user-agent': UA, 'accept-encoding': 'gzip', **sig,
    }
    resp = net.http('POST', url, headers=headers, data=body.encode('utf-8'),
                    step='dsign', endpoint=endpoint, layer=DEVICE)
    cookies = grab_cookies(resp)
    raw = resp.content
    if resp.status_code != 200 or len(raw) == 0:
        raise StepError('dsign', DEVICE, endpoint=endpoint, http=resp.status_code,
                        server_msg=f'len={len(raw)}',
                        hint='dsign http≠200/empty — device bị ban hoặc device-guard đổi.')
    txt = body_text(resp)
    try:
        j = json.loads(txt)
    except Exception as e:
        raise StepError('dsign', DEVICE, endpoint=endpoint, http=resp.status_code, server_msg=txt[:200],
                        hint='dsign trả non-JSON.', cause=e)
    try:
        sd = json.loads(base64.b64decode(j['tt-device-guard-server-data']).decode('utf-8'))
    except Exception as e:
        raise StepError('dsign', DEVICE, endpoint=endpoint, http=resp.status_code, raw=j,
                        hint='thiếu/không decode được tt-device-guard-server-data — device-guard đổi.', cause=e)
    ts_sign = sd.get('ts_sign', '')
    if not ts_sign and j.get('tt-ticket-guard-server-data'):
        try:
            ts_sign = json.loads(base64.b64decode(j['tt-ticket-guard-server-data']).decode('utf-8')).get('ts_sign', '')
        except Exception:
            ts_sign = ''
    s_val = '?'
    try:
        s_val = json.loads(sd['device_token'].split('|')[1]).get('s')
    except Exception:
        pass
    return {'device_token': sd['device_token'], 'dtoken_sign': sd['dtoken_sign'], 'priv': priv,
            'ec_pub': ec_pub, 'ts_sign': ts_sign, 's': s_val, 'cookies': cookies}


# ── device-guard + ticket-guard headers (dreq_sign / req_sign over EC key) ──
def _ec_sign(priv, data):
    return priv.sign(data.encode('latin1'), ec.ECDSA(hashes.SHA256()))  # DER, randomized


def guards(d, api_path, ts, ticket='', ts_sign=None):
    if ts_sign is None:
        ts_sign = d.get('ts_sign', '')
    try:
        dg_der = _ec_sign(d['priv'], f'device_token={d["device_token"]}&path={api_path}&timestamp={ts}')
        tg_der = _ec_sign(d['priv'], f'ticket={ticket}&path={api_path}&timestamp={ts}')
    except Exception as e:
        raise StepError('guards', GUARD, endpoint=api_path,
                        hint='ECDSA sign fail — EC keypair từ dsign lỗi.', cause=e)
    dg_client = json.dumps({
        'device_token': d['device_token'], 'timestamp': ts, 'req_content': 'device_token,path,timestamp',
        'dtoken_sign': d['dtoken_sign'], 'dreq_sign': base64.b64encode(dg_der).decode(),
    }, separators=(',', ':'))
    tg_client = json.dumps({
        'req_content': 'ticket,path,timestamp', 'req_sign': base64.b64encode(tg_der).decode(),
        'timestamp': ts, 'ts_sign': ts_sign,
    }, separators=(',', ':'))
    return {
        'tt-device-guard-client-data': base64.b64encode(dg_client.encode('utf-8')).decode(),
        'tt-device-guard-iteration-version': '1',
        'tt-ticket-guard-public-key': base64.b64encode(d['ec_pub']).decode(),
        'tt-ticket-guard-version': '3',
        'tt-ticket-guard-iteration-version': '0',
        'tt-ticket-guard-client-data': base64.b64encode(tg_client.encode('utf-8')).decode(),
    }
