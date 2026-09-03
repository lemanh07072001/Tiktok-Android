"""re/py/edata.py — codec edata captcha TikTok (port mobile/edata_codec.mjs + captcha_api_solve.answerEdata).
  edata = base64( 0x01 || key(32) || nonce(12) || ChaCha20(plaintext, key, iv = 0000_0000 || nonce) )
  ChaCha20 counter=0; key+nonce nhúng trong edata (obfuscation) → encrypt bằng key ngẫu nhiên OK.
Node crypto 'chacha20' iv = concat(alloc(4), nonce) (16B) == Python ChaCha20(key, b'\\x00'*4 + nonce).
"""
import os
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

DRAGW = 348   # widthView omocaptcha (348-space) = distance


def decrypt_edata(b64):
    ed = base64.b64decode(b64)
    if len(ed) < 45 or ed[0] != 1:
        raise ValueError(f'edata invalid (ver={ed[0] if ed else "?"})')
    key, nonce, ct = ed[1:33], ed[33:45], ed[45:]
    dec = Cipher(algorithms.ChaCha20(key, b'\x00\x00\x00\x00' + nonce), mode=None).decryptor()
    pt = (dec.update(ct) + dec.finalize()).decode('utf-8', 'replace')
    try:
        return json.loads(pt)
    except Exception:
        return pt


def encrypt_edata(obj):
    key, nonce = os.urandom(32), os.urandom(12)
    pt = (obj if isinstance(obj, str) else json.dumps(obj, separators=(',', ':'))).encode('utf-8')
    enc = Cipher(algorithms.ChaCha20(key, b'\x00\x00\x00\x00' + nonce), mode=None).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return base64.b64encode(bytes([1]) + key + nonce + ct).decode()


# ── CRC32 (IEEE) cho hashcash PoW ──
_CRC = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC.append(_c & 0xFFFFFFFF)


def crc32(buf):
    c = 0xFFFFFFFF
    for b in buf:
        c = _CRC[(c ^ b) & 0xFF] ^ (c >> 8)
    return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF


def hashcash_ok(answer, question):
    rb = question.get('required_bits', 0) or 0
    if rb <= 0:
        return True
    stamp = (question.get('stamp', 0) or 0) & 0xFFFFFFFF
    return (((crc32(answer.encode('utf-8')) ^ stamp) & 0xFFFFFFFF) >> (32 - rb)) == 0


def solve_hashcash(question):
    prefix = str(question.get('prefix', ''))
    ch = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    for _ in range(50_000_000):
        suf = ''.join(ch[b % len(ch)] for b in os.urandom(8))
        ans = prefix + suf
        if hashcash_ok(ans, question):
            return ans
    raise RuntimeError('hashcash không giải được (required_bits quá lớn?)')


# ── answer edata ──
def answer_slide(challenge, distance):
    """Slide answer 90-điểm (bám captcha_api_solve.answerEdata). distance = end.x (348-space)."""
    ch = challenge['data']['challenges'][0]
    reply = []
    for i in range(1, 91):
        p = i / 90
        reply.append({'x': round(distance * min(1, p / 0.92)), 'y': 3 + (i % 3),
                      'relative_time': round(20 + 1250 * (p ** 1.4))})
    reply[-1]['x'] = distance
    base = {'id': ch['id'], 'modified_img_width': DRAGW, 'drag_width': DRAGW, 'mode': 'slide',
            'reply': reply, 'models': {}, 'reply2': [], 'models2': {}, 'events': '{"userMode":0}'}
    return encrypt_edata({
        'modified_img_width': DRAGW, 'id': ch['id'], 'mode': 'slide', 'reply': reply, 'models': {},
        'log_params': {}, 'reply2': [], 'models2': {}, 'drag_width': DRAGW, 'version': 2,
        'verify_id': challenge['data']['verify_id'], 'verify_requests': [base], 'events': '{"userMode":0}'})


def answer_hashcash(challenge):
    """Hashcash PoW self-solve (không cần omocaptcha)."""
    data = challenge['data']
    ch = data['challenges'][0]
    ans = solve_hashcash(ch['question'])
    return encrypt_edata({
        'id': ch['id'], 'mode': 'hashcash', 'reply': [], 'models': {}, 'log_params': {}, 'reply2': [],
        'models2': {}, 'answer': ans, 'version': 2, 'verify_id': data['verify_id'],
        'verify_requests': [{'id': ch['id'], 'mode': 'hashcash', 'answer': ans,
                             'challenge_code': ch['challenge_code']}]})
