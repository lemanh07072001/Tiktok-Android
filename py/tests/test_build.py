"""re/py/tests/test_build.py — integration đường DỰNG request (build-only, KHÔNG gửi TikTok).
Spawn fake /sign in-process → verify build_call ráp header metasec + guards + query đúng.
  python re/py/tests/test_build.py
"""
import os
import sys
import json
import base64
import hashlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from cryptography.hazmat.primitives.asymmetric import ec

import signer
import login
import device

_fails = []


def check(name, cond, extra=''):
    print(('✓' if cond else '✗') + ' ' + name + (f'  {extra}' if extra else ''))
    if not cond:
        _fails.append(name)


# ── fake /sign server ──
_last = {}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        ln = int(self.headers.get('content-length', 0))
        _last['payload'] = json.loads(self.rfile.read(ln) or b'{}')
        out = json.dumps({'X-Argus': 'AR', 'X-Gorgon': 'GO', 'X-Ladon': 'LA', 'X-Khronos': '123'}).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


srv = HTTPServer(('127.0.0.1', 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
signer.SIGNER_URL = f'http://127.0.0.1:{srv.server_address[1]}'

# ── synth device-guard dict (EC keypair thật) ──
priv = ec.generate_private_key(ec.SECP256R1())
d = {'priv': priv, 'ec_pub': device._ec_pub_bytes(priv),
     'device_token': '1|{"s":1}', 'dtoken_sign': 'DTS', 'ts_sign': 'TSS'}
dev = {'device_id': '111', 'install_id': '222'}

params = {'password': login.enc('p'), 'account_sdk_source': 'app', 'multi_login': '1',
          'mix_mode': '1', 'username': login.enc('u')}
c = login.build_call(dev, d, '/passport/user/login/', params=params)
h = c['headers']

check('sign bridge trả X-Argus', h.get('X-Argus') == 'AR')
check('có X-Gorgon/Ladon/Khronos', h.get('X-Gorgon') == 'GO' and h.get('X-Ladon') == 'LA' and h.get('X-Khronos') == '123')
check('có device-guard client-data', bool(h.get('tt-device-guard-client-data')))
check('user/login BỎ ticket-guard-client-data', 'tt-ticket-guard-client-data' not in h)
check('có ticket-guard-public-key', bool(h.get('tt-ticket-guard-public-key')))
check('url đúng host+path', c['url'].startswith('https://api16-normal-c-alisg.tiktokv.com/passport/user/login/?'))
check('body non-empty', bool(c['body']))
check('x-ss-stub == md5(body)', h.get('x-ss-stub') == hashlib.md5(c['body'].encode()).hexdigest().upper())
check('genuine header oec-cs có mặt', h.get('oec-cs-sdk-version', '').startswith('v10.02'))
# signer nhận cả hdr lẫn headerBlock (khớp oracle + server.mjs)
check('payload /sign có hdr+headerBlock', 'hdr' in _last.get('payload', {}) and 'headerBlock' in _last['payload'])
check('block ký chứa cookie store-idc', 'store-idc=alisg' in _last['payload']['hdr'])

srv.shutdown()
print()
if _fails:
    print(f'FAIL {len(_fails)}: ' + ', '.join(_fails))
    sys.exit(1)
print('ALL BUILD TESTS PASS')
