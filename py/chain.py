"""re/py/chain.py — runner: orchestrate full login-2135 chain, in ✓/✗ TỪNG BƯỚC.
Bám ground-truth note 26. Khi TikTok update → dừng đúng bước hỏng + StepError.report() gợi ý.
"""
import sys

from errors import StepError, LOGIN, AAAS, EMAIL
import device
import login
import aaas
import session
from profiles import P
from signer import SIGNER_URL
from net import PROXY_ON
from ui import ok as _ok, fail as _fail, YELLOW, RESET   # màu ✓/✗ + ANSI (tự bật trên Windows)

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')   # Windows console cp1252 → in ✓/✗ được
except Exception:
    pass


def _msg(lg):
    return ((lg.get('j') or {}).get('message'))


def _ec_num(lg):
    return ((lg.get('j') or {}).get('data') or {}).get('error_code')


def _check(lg, step, layer, allow=()):
    """success → 'success'; ec ∈ allow → trả ec; còn lại raise StepError (step = hàm đã gọi)."""
    if _msg(lg) == 'success':
        return 'success'
    ec = _ec_num(lg)
    if ec in allow:
        return ec
    raise StepError(step, layer, endpoint=lg.get('endpoint'), http=lg.get('status'), ec=ec,
                    server_msg=_msg(lg), raw=lg.get('j'))


def _solve_if_captcha(res, dev, d, retry_fn, step):
    """Nếu res = 1105/1108 (captcha) → giải captcha (omocaptcha slide / hashcash) rồi RETRY request 1 lần."""
    if _ec_num(res) not in (1105, 1108):
        return res
    ec = _ec_num(res)
    print(f'{YELLOW}⚠{RESET} {step}: ec={ec} (captcha) → đang giải…', flush=True)
    try:
        import captcha as _cap
    except Exception as e:
        _fail(f'  không nạp được module captcha: {e}')
        return res
    cr = _cap.solve_captcha(dev, d, log=lambda m: print(f'{YELLOW}{m}{RESET}', flush=True))
    if cr['ok']:
        _ok(f'{step} captcha', f'PASS sau {cr["tries"]} lần → retry')
        return retry_fn()
    _fail(f'  captcha KHÔNG giải được sau {cr["tries"]} lần '
          f'(slide cần OMO_API_KEY; hoặc đổi IP/account sạch)')
    return res


def run_login_chain(account, read_code=None, do_warmup=True, dev=None):
    """account = {username, password, email, mailpass?}. read_code(email)->code (bắt buộc nếu 2135).
    dev: nếu cấp (device persist/provided) → BỎ device_register, dùng luôn. Trả
    {'ok':bool, 'session'|'error', 'step', 'dev', 'd'} (dev/d để write-op follow sau login)."""
    u, pw, email = account['username'], account['password'], account.get('email', '')
    d = None
    print('── re/py login-2135 chain ──')
    print(f'   signer={SIGNER_URL or "(CHƯA SET!)"}  proxy={"ON" if PROXY_ON else "off"}')
    _ok('01 profile', f"model={P['model']} brand={P['brand']} os={P['osv']}")
    try:
        # 02 device_register (hoặc dùng dev đã cấp: persist per-account / provided ở account.txt)
        if dev is None:
            dev = device.register_device()
            _ok('02 register_device', f"did={dev['device_id']} iid={dev['install_id']} new_user={dev.get('new_user')}")
        else:
            _ok('02 device (persist/provided)', f"did={dev['device_id']} iid={dev['install_id']}")

        # 03 dsign + guards
        d = device.dsign(dev)
        _ok('03 dsign+guards', f"s={d.get('s')} ts_sign={'yes' if d.get('ts_sign') else 'no'}")

        # 04 seed cookies (odin_tt device) từ register + dsign vào JAR login
        login.seed_cookies(dev.get('cookies'))
        login.seed_cookies(d.get('cookies'))
        _ok('04 seed_cookies', f"jar={list(login.JAR.keys())}")

        # 05 warmup (best-effort)
        if do_warmup:
            keys = login.warmup(dev, d)
            _ok('05 warmup', f"jar={keys}")

        # 06 pre_check (best-effort, chỉ log)
        try:
            pc = login.pre_check(u, dev, d)
            _ok('06 pre_check', f"status={pc['status']} ec={_ec_num(pc)} msg={_msg(pc)}")
        except StepError as e:
            print('  (06 pre_check bỏ qua) ' + str(e))

        # 07 user_login → success | 2135 | ec7 | 1105/1108(captcha→giải rồi retry)
        lg = login.user_login(u, pw, dev, d)
        lg = _solve_if_captcha(lg, dev, d, lambda: login.user_login(u, pw, dev, d), 'user_login')
        res = _check(lg, 'user_login', LOGIN, allow=(2135,))
        if res == 'success':
            _ok('07 user_login', 'ĐĂNG NHẬP THẲNG (account chưa bị cờ)')
            s = session.session_from(lg, dev)
            _ok('DONE', f"uid={s['uid']} session_key={s['session_key'][:12]}…")
            return {'ok': True, 'session': s, 'step': 'user_login', 'dev': dev, 'd': d}
        # 2135 branch
        dc = lg.get('dc') or {}
        ticket = dc.get('passport_ticket')
        extra = dc.get('extra') or []
        pid = (extra[0].get('pseudo_id') if extra else None) or aaas.new_pseudo_id()
        if not ticket:
            raise StepError('user_login', LOGIN, endpoint=lg.get('endpoint'), http=lg.get('status'), ec=2135,
                            raw=lg.get('dc') or lg.get('j'),
                            hint='2135 nhưng thiếu passport_ticket ở header x-tt-verify-idv-decision-conf — '
                                 'header đổi tên/format.')
        _ok('07 user_login', f"2135 (bị cờ, đúng kỳ vọng) ticket={ticket[:10]}… pid={pid[:10]}…")

        # 08 challenges → factor type=2 (email)
        ch = aaas.challenges(dev, d, ticket)
        _check(ch, 'challenges', AAAS, allow=(0,))
        factors = ((ch.get('j') or {}).get('data') or {}).get('challenges') or \
                  ((ch.get('j') or {}).get('challenges')) or []
        types = [c.get('type') for c in factors] if factors else []
        if 2 not in types:
            raise StepError('challenges', AAAS, endpoint=ch.get('endpoint'), http=ch.get('status'),
                            raw=ch.get('j'), hint=f'không có factor type=2 (email). types={types}. Luồng verify đổi.')
        _ok('08 challenges', f"factors={types} (2=email)")

        # 09 auth_send action=3 → gửi mã email
        se = aaas.auth_send(dev, d, ticket, pid)
        _check(se, 'auth_send', AAAS)
        _ok('09 auth_send', 'server đã gửi mã tới email')

        # 10 đọc mã email
        if read_code is None:
            raise StepError('read_code', EMAIL, hint='Chưa cấp read_code(email)->code. '
                            'Set RE_CODE=<code>, hoặc dùng mailtm creds, hoặc nhập stdin (run.py).')
        code = read_code(email)
        if not code:
            raise StepError('read_code', EMAIL, hint='Không lấy được mã từ email (timeout/không tới).')
        _ok('10 read_code', f"code={code}")

        # 11 auth_verify action=4 → success + d_ticket
        vf = aaas.auth_verify(dev, d, ticket, pid, code)
        _check(vf, 'auth_verify', AAAS)
        d_ticket = vf.get('d_ticket', '')
        _ok('11 auth_verify', f"verified d_ticket={'yes' if d_ticket else 'NO(!)'}")

        # 12 relogin #7 → session (giải captcha nếu 1105/1108 rồi retry)
        rl = session.relogin(u, pw, dev, d, ticket, d_ticket)
        rl = _solve_if_captcha(rl, dev, d, lambda: session.relogin(u, pw, dev, d, ticket, d_ticket), 'relogin')
        _check(rl, 'relogin', LOGIN)
        s = session.session_from(rl, dev)
        _ok('12 relogin', f"uid={s['uid']} session_key={s['session_key'][:12]}…")
        print(f'✓ DONE  session_key={s["session_key"]}  user_id={s["uid"]}')
        return {'ok': True, 'session': s, 'step': 'relogin', 'dev': dev, 'd': d}

    except StepError as e:
        print()
        _fail(e.report())
        return {'ok': False, 'error': e, 'step': e.step, 'dev': dev, 'd': d}


if __name__ == '__main__':
    # thử nghiệm nhanh: python re/py/chain.py "<user>|<pass>|<email>"
    from run import parse_account, make_reader
    acc = parse_account(sys.argv[1]) if len(sys.argv) > 1 else None
    if not acc:
        print('usage: python re/py/chain.py "<user>|<pass>|<email>|<mailpass>"')
        sys.exit(2)
    r = run_login_chain(acc, read_code=make_reader(acc))
    sys.exit(0 if r['ok'] else 1)
