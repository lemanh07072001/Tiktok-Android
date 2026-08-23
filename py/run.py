"""re/py/run.py — CLI: chạy full login-2135 chain cho 1 account.
  python re/py/run.py "<user>|<password>|<email>|<mailpass>"
Đọc mã email: RE_CODE env (one-shot) → mail.tm (nếu có <mailpass>) → nhập stdin.
"""
import os
import sys
import json

# đảm bảo import sibling khi gọi từ nơi khác
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from chain import run_login_chain  # noqa: E402


def parse_account(s):
    """"<user>|<password>|<email>|<mailpass>" → dict. mailpass optional (bỏ '@' suffix nhãn kiểu MailTM@)."""
    if not s:
        return None
    f = [x.strip() for x in s.split('|')]
    if len(f) < 2:
        return None
    acc = {'username': f[0], 'password': f[1]}
    if len(f) > 2 and f[2]:
        acc['email'] = f[2]
    if len(f) > 3 and f[3]:
        acc['mailpass'] = f[3]   # KHÔNG rstrip '@' — pass mail.tm có thể chứa '@' (vd "MailTM@")
    return acc


def make_reader(acc):
    """Trả read_code(email)->code theo nguồn sẵn có."""
    if os.environ.get('RE_CODE'):
        return lambda email=None: os.environ['RE_CODE']
    if acc.get('email') and acc.get('mailpass'):
        import mailtm

        def _mail(email=None):
            try:
                return mailtm.read_code(email or acc['email'], acc['mailpass'])
            except Exception as e:
                print(f'  (đọc mail lỗi: {e}) — set RE_CODE=<code> để nhập tay')
                return None
        return _mail
    def _stdin(email=None):
        try:
            return input(f'Nhập mã verify gửi tới {email or acc.get("email")}: ').strip()
        except EOFError:
            return None
    return _stdin


def main():
    if len(sys.argv) < 2:
        print('usage: python re/py/run.py "<user>|<password>|<email>|<mailpass>"')
        return 2
    acc = parse_account(sys.argv[1])
    if not acc:
        print('account sai định dạng — cần tối thiểu "<user>|<password>"')
        return 2
    r = run_login_chain(acc, read_code=make_reader(acc))
    if r['ok']:
        print('\nSESSION:', json.dumps(r['session'], ensure_ascii=False))
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
