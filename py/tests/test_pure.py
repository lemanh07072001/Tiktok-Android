"""re/py/tests/test_pure.py — verify các hàm THUẦN offline (không mạng/signer).
Bắt regression khi TikTok update: header-order block, enc, guards ECDSA, query encode.
  python re/py/tests/test_pure.py
"""
import os
import sys
import json
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

import signer
import login
import device
import profiles
from net import qs
from errors import StepError

_fails = []


def check(name, cond, extra=''):
    print(('✓' if cond else '✗') + ' ' + name + (f'  {extra}' if extra else ''))
    if not cond:
        _fails.append(name)


# 1. enc/dec XOR 0x05
check('enc("a")=="64"', login.enc('a') == '64', login.enc('a'))
check('enc("A")=="44"', login.enc('A') == '44')
check('enc/dec round-trip', login.dec(login.enc('Hello@123_ăâ')) == 'Hello@123_ăâ')

# 2. md5_stub known vector
check('md5_stub("a=1&b=2")', signer.md5_stub('a=1&b=2') == 'ED04C91CF6F6AB5A01A31C0295C5DA34',
      signer.md5_stub('a=1&b=2'))
check('md5_stub(None) is None', signer.md5_stub(None) is None)

# 3. metasec_block — THỨ TỰ header (regression guard)
blk = signer.metasec_block(stub='ABC', req_ticket=123, tt_token='', cookie='store-idc=alisg', ua='UA/1')
expect = ['x-ss-stub', 'ABC', 'content-type', 'application/x-www-form-urlencoded; charset=UTF-8',
          'x-ss-req-ticket', '123', 'x-tt-token', '', 'cookie', 'store-idc=alisg',
          'user-agent', 'UA/1', 'sdk-version', '2', 'passport-sdk-version', '1']
check('metasec_block order+content', blk.split('\r\n') == expect)
blk2 = signer.metasec_block(stub=None, req_ticket=1, tt_token='t', cookie='', ua='UA/1')
check('metasec_block bỏ x-ss-stub khi None', not blk2.startswith('x-ss-stub'))

# 4. guards() — ECDSA P-256 dreq_sign/req_sign verify được bằng pubkey
priv = ec.generate_private_key(ec.SECP256R1())
pub_bytes = device._ec_pub_bytes(priv)
d = {'priv': priv, 'ec_pub': pub_bytes, 'device_token': '1|{"s":1}', 'dtoken_sign': 'DTS', 'ts_sign': 'TSS'}
path, ts = '/passport/user/login/', 1699999999
g = guards_out = device.guards(d, path, ts, ticket='TK')
dg = json.loads(base64.b64decode(g['tt-device-guard-client-data']))
tg = json.loads(base64.b64decode(g['tt-ticket-guard-client-data']))
pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)


def _verify(sig_b64, msg):
    try:
        pub.verify(base64.b64decode(sig_b64), msg.encode('latin1'), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


check('device-guard req_content', dg['req_content'] == 'device_token,path,timestamp')
check('dreq_sign verify', _verify(dg['dreq_sign'], f'device_token={d["device_token"]}&path={path}&timestamp={ts}'))
check('dtoken_sign passthrough', dg['dtoken_sign'] == 'DTS')
check('ticket-guard req_content', tg['req_content'] == 'ticket,path,timestamp')
check('req_sign verify', _verify(tg['req_sign'], f'ticket=TK&path={path}&timestamp={ts}'))
check('ts_sign passthrough', tg['ts_sign'] == 'TSS')
check('tg-public-key == ec_pub', g['tt-ticket-guard-public-key'] == base64.b64encode(pub_bytes).decode())
check('tg-version=3 iter=0 dg-iter=1',
      g['tt-ticket-guard-version'] == '3' and g['tt-ticket-guard-iteration-version'] == '0'
      and g['tt-device-guard-iteration-version'] == '1')

# 5. qs() giữ '*' không-encode, encode '/'
enc_qs = qs({'resolution': '1440*2560', 'tz': 'Asia/Ho_Chi_Minh'})
check('qs giữ *', '1440*2560' in enc_qs, enc_qs)
check('qs encode /', '%2F' in enc_qs)

# 6. pass_query đủ field bắt buộc
pq = login.pass_query({'device_id': 'DID', 'install_id': 'IID'})
check('pass_query device_id/iid', pq.get('device_id') == 'DID' and pq.get('iid') == 'IID')
check('pass_query aid=1233', pq.get('aid') == '1233')

# 7. profiles.pick deterministic
check('profiles.pick(2)', profiles.pick(2) is profiles.PROFILES[2])
check('profiles.pick wrap', profiles.pick(9) is profiles.PROFILES[9 % len(profiles.PROFILES)])

# 8. sign_metasec raise StepError khi thiếu SIGNER_URL
_old = signer.SIGNER_URL
signer.SIGNER_URL = ''
try:
    signer.sign_metasec('https://x/', 'blk', 1)
    check('sign_metasec raise khi thiếu SIGNER_URL', False)
except StepError as e:
    check('sign_metasec raise khi thiếu SIGNER_URL', e.layer == 'SIGN' and e.hint is not None)
finally:
    signer.SIGNER_URL = _old

print()
if _fails:
    print(f'FAIL {len(_fails)}: ' + ', '.join(_fails))
    sys.exit(1)
print('ALL PURE TESTS PASS')
