"""re/py/net.py — HTTP qua proxy (đổi IP egress) + giải nén + cookie thủ công.
Port từ re/src/net.mjs. Cookie quản THỦ CÔNG (như .mjs JAR) — session KHÔNG tự lưu cookie
(để logic strip/seed cookie ở login/aaas kiểm soát hoàn toàn).

  PROXY_URL=http://user:pass@host:port  hoặc  socks5://user:pass@host:port
"""
import os
import gzip
import time
import zlib
import urllib.parse
from http.cookiejar import DefaultCookiePolicy

import requests

from errors import StepError, NET

try:
    import brotli
except Exception:
    brotli = None
try:
    import zstandard
except Exception:
    zstandard = None

PROXY_URL = os.environ.get('PROXY_URL')
_TIMEOUT = int(os.environ.get('PROXY_TIMEOUT_MS', '30000')) / 1000.0
PROXY_ON = bool(PROXY_URL)


def _make_session():
    s = requests.Session()
    # từ chối lưu cookie (quản thủ công như .mjs JAR)
    s.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    if PROXY_URL:
        s.proxies = {'http': PROXY_URL, 'https': PROXY_URL}
    return s


SESSION = _make_session()


def now_ms():
    return int(time.time() * 1000)


def now_s():
    return int(time.time())


def qs(d):
    """Encode query khớp URLSearchParams: giữ '*' không-encode, space→'+', hex uppercase."""
    return urllib.parse.urlencode(d, safe='*')


def http(method, url, headers=None, data=None, step='http', endpoint=None, layer=NET):
    """1 request qua proxy. data = bytes/str cho POST. Raise StepError(NET) khi lỗi mạng."""
    try:
        return SESSION.request(method, url, headers=headers, data=data, timeout=_TIMEOUT)
    except Exception as e:
        raise StepError(step, layer, endpoint=endpoint,
                        hint='Lỗi mạng/proxy — check PROXY_URL còn sống + host reachable.', cause=e)


def _gunzip(b):
    try:
        return gzip.decompress(b)
    except Exception:
        return zlib.decompress(b)


def body_text(resp):
    """Trả text đã giải nén. requests thường tự decode content-encoding; fallback gzip/brotli/zstd."""
    raw = resp.content
    # requests đã content-decode → thử utf-8 thẳng
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        pass
    for fn in (_gunzip,
               (brotli.decompress if brotli else None),
               ((lambda b: zstandard.ZstdDecompressor().decompress(b)) if zstandard else None)):
        if fn is None:
            continue
        try:
            return fn(raw).decode('utf-8')
        except Exception:
            continue
    return raw.decode('utf-8', 'replace')


def grab_cookies(resp):
    """Set-Cookie → dict (giữ đủ, không mất duplicate như resp.headers gộp)."""
    o = {}
    try:
        for c in resp.raw.headers.getlist('Set-Cookie'):
            kv = c.split(';')[0]
            i = kv.find('=')
            if i > 0:
                o[kv[:i].strip()] = kv[i + 1:].strip()
    except Exception:
        try:
            o = resp.cookies.get_dict()
        except Exception:
            pass
    return o
