"""re/py/mailtm.py — mail.tm client tối giản (INFRA, không phải RE logic). Đọc mã verify từ email.
Dùng bởi run.py khi account có <mailpass>. Gọi requests THẲNG (không qua proxy egress TikTok).
"""
import re
import time
import requests

_API = 'https://api.mail.tm'


def _token(address, password):
    r = requests.post(_API + '/token', json={'address': address, 'password': password}, timeout=20)
    r.raise_for_status()
    return r.json()['token']


def _extract_code(text):
    if not text:
        return None
    for pat in (r'\b(\d{6})\b', r'\b(\d{5})\b', r'\b(\d{4})\b'):
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def read_code(address, password, timeout_s=120, since_ts=None):
    """Poll mail.tm tới khi có mã (4-6 số) trong mail mới. since_ts = chỉ mail sau mốc này."""
    tok = _token(address, password)
    h = {'Authorization': 'Bearer ' + tok}
    since_ts = since_ts or time.time()
    deadline = time.time() + timeout_s
    seen = set()
    while time.time() < deadline:
        try:
            lst = requests.get(_API + '/messages', headers=h, timeout=20).json().get('hydra:member', [])
        except Exception:
            time.sleep(3)
            continue
        for m in lst:
            mid = m.get('id')
            if mid in seen:
                continue
            seen.add(mid)
            code = _extract_code(m.get('subject', ''))
            if not code:
                try:
                    full = requests.get(_API + '/messages/' + mid, headers=h, timeout=20).json()
                    code = _extract_code(full.get('text') or '') or _extract_code(full.get('subject') or '')
                except Exception:
                    code = None
            if code:
                return code
        time.sleep(4)
    return None
