"""re/py/errors.py — structured per-step errors.

Mỗi step function raise StepError khi hỏng. Runner (chain.py) in ✓/✗ từng bước và StepError
làm rõ HÀM/ENDPOINT nào đổi khi TikTok update. Hai lớp lỗi:
  - hạ tầng : network / non-JSON / sign fail / thiếu field shape  → hàm tự raise (step = tên hàm)
  - business: ec ngoài kỳ vọng                                     → chain raise, hint từ HINTS
"""
import json

# ── layer tags ──
SIGN = 'SIGN'
NET = 'NET'
DEVICE = 'DEVICE'
GUARD = 'GUARD'
LOGIN = 'LOGIN'
AAAS = 'AAAS'
SESSION = 'SESSION'
EMAIL = 'EMAIL'


class StepError(Exception):
    def __init__(self, step, layer, endpoint=None, http=None, ec=None,
                 server_msg=None, hint=None, raw=None, cause=None):
        self.step = step
        self.layer = layer
        self.endpoint = endpoint
        self.http = http
        self.ec = ec
        self.server_msg = server_msg
        self.hint = hint or hint_for(step, ec)
        self.raw = raw
        self.cause = cause
        super().__init__(f'[{layer}] {step}: ec={ec} http={http} {server_msg or ""}'.rstrip())

    def report(self):
        """Chuỗi nhiều dòng cho runner in ra."""
        lines = [f'✗ {self.step}  [{self.layer}]']
        if self.endpoint:
            lines.append(f'    endpoint {self.endpoint}')
        meta = []
        if self.http is not None:
            meta.append(f'http={self.http}')
        if self.ec is not None:
            meta.append(f'ec={self.ec}')
        if meta:
            lines.append('    ' + '  '.join(meta))
        if self.server_msg:
            lines.append(f'    msg: {self.server_msg}')
        if self.hint:
            lines.append(f'    hint: {self.hint}')
        if self.cause is not None:
            lines.append(f'    cause: {type(self.cause).__name__}: {self.cause}')
        if self.raw is not None:
            r = self.raw if isinstance(self.raw, str) else json.dumps(self.raw, ensure_ascii=False)
            lines.append('    raw: ' + r[:600])
        return '\n'.join(lines)


# ── HINTS: gợi ý theo (step, ec). '*' = mọi step. Bám ground-truth note 26. ──
HINTS = {
    ('*', 7): "ec7 = velocity/rate-limit theo device_id + IP-register (note 26). KHÔNG phải "
              "X-Argus/recipe/device-trust. Mint device trên IP residential SẠCH, login CÙNG IP; "
              "throttle đã trip reset = chờ giờ.",
    ('*', 1105): "ec1105 = captcha required — device forge/untrusted hoặc IP bẩn. Cần trusted device "
                 "(dsign s=1) + IP sạch, hoặc giải captcha.",
    ('*', 1108): "ec1108 = captcha verify-center (slide/whirl) — account/device/IP BỊ CỜ đòi giải captcha "
                 "(note 22: device real/aged hay dính; re-login CÙNG account nhiều lần cũng trip). Cách qua: "
                 "đổi PROXY IP SẠCH + account CHƯA login gần đây; hoặc wire captcha-solver (omocaptcha/chrome). "
                 "KHÔNG phải lỗi ký/port — 1 IP+account sạch là qua.",
    ('*', 2135): "ec2135 = account bị-cờ, cần verify. Ở user_login đây là ĐÚNG kỳ vọng → đi tiếp aaas.",
    ('*', 8): "ec8 = sai tham số / rule bị chặn (send_code, register). So lại params vs ground-truth.",
    ('*', 1057): "ec1057 = account đã tồn tại / trạng thái xung đột.",
    ('*', 2027): "ec2027 = giới hạn/verify khác. Đọc raw + so ground-truth mitm.",
    ('sign_metasec', None): "SIGNER_URL/METASEC_ORACLE chưa set hoặc signer chết. Python không tự ký "
                            "metasec. Chạy mobile/server/server.mjs (:8799) hoặc phone-oracle.",
    ('register_device', None): "device_register không trả device_id_str/install_id_str — schema đổi "
                               "hoặc bị chặn (IP/fingerprint). Check raw + query fields vs ground-truth.",
    ('dsign', None): "dsign http≠200 hoặc thiếu tt-device-guard-server-data — device bị ban, "
                     "hoặc device-guard đổi. Check http status + raw.",
    ('challenges', None): "challenges không trả factor type=2 (email) — server đổi luồng verify, "
                          "hoặc ticket/pseudo_id sai.",
    ('relogin', None): "relogin #7 fail — check header x-tt-passport-ticket + d_ticket (từ authenticate) "
                       "+ cookie strip 5-key (note 26). Body phải byte-identical login gốc.",
}


def hint_for(step, ec):
    """Tra hint: (step,ec) → ('*',ec) → (step,None). ec-cụ-thể (vd 1108 captcha) thắng hint step-generic."""
    for key in ((step, ec), ('*', ec), (step, None)):
        if key in HINTS and HINTS[key]:
            return HINTS[key]
    return None
