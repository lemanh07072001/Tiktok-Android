"""re/py/tool/worker.py — chạy login-2135 chain cho 1 account (mỗi account 1 device BỀN), in ✓/✗ từng bước,
   thành công thì FETCH + in INFO (follower/following/video/likes...). Port re/tool/worker.mjs.
  ACCOUNT env | argv[1] = "user|pass|email|mailpass[|did|iid|openudid|cdid|gaid]"
  PROXY_URL  : mỗi tiến trình 1 IP (net.py egress).  SIGNER_URL/METASEC_ORACLE: signer.
  FOLLOW=<uniqueId> [FOLLOW_TYPE=1|0] : sau login → follow + verify STUCK/shadow.
  SAVE_SESSION=<path> : lưu session ra file (tái dùng bằng check_follow, KHÔNG re-login).
"""
import os
import sys
import json
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPY = os.path.dirname(HERE)
sys.path.insert(0, REPY)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import net  # noqa: E402  (side-effect: proxy egress từ PROXY_URL)
import ui  # noqa: E402  (màu + box console)
import session as sess_mod  # noqa: E402
import follow as follow_mod  # noqa: E402
from net import now_ms  # noqa: E402
from chain import run_login_chain  # noqa: E402
from run import parse_account, make_reader  # noqa: E402

OUT = os.path.join(HERE, 'out')
DEV = os.path.join(HERE, 'devices')   # mỗi account 1 device_id BỀN


def safe_name(s):
    return ''.join(c if (c.isalnum() or c in '.-_') else '_' for c in str(s))[:60]


def append_fail(user, step, ec):
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, 'fail.txt'), 'a', encoding='utf-8') as f:
            f.write(f'{user}\t{step}\tec={ec or ""}\n')
    except Exception:
        pass


def finish(code=0):
    if os.environ.get('NO_PAUSE'):
        return code
    try:
        input('\n[Enter để đóng cửa sổ] ')
    except EOFError:
        pass
    return code


def show_info(session):
    """FETCH + in INFO chi tiết + lưu out/<uid>.json."""
    uid = session['uid']
    u = {}
    try:
        prof = sess_mod.call_authed(session, '/aweme/v1/user/profile/self/', extra_query={'user_id': uid})
        pj = prof.get('j') or {}
        u = (pj.get('data') or {}).get('user') or pj.get('user') or {}
    except Exception:
        pass
    acc = {}
    try:
        ai = sess_mod.call_authed(session, '/passport/account/info/v2/', extra_query={'scene': 'normal'})
        acc = (ai.get('j') or {}).get('data') or {}
    except Exception:
        pass
    info = {
        'ok': bool(u.get('uid') or u.get('nickname')), 'uid': uid,
        'nickname': u.get('nickname'), 'unique_id': u.get('unique_id'), 'signature': u.get('signature'),
        'region': u.get('region'), 'follower_count': u.get('follower_count'),
        'following_count': u.get('following_count'), 'aweme_count': u.get('aweme_count'),
        'total_favorited': u.get('total_favorited'), 'favoriting_count': u.get('favoriting_count'),
        'create_time': u.get('create_time'), 'email': acc.get('email'), 'mobile': acc.get('mobile'),
        'has_password': acc.get('has_password'),
    }
    print()
    ui.box_top(info['unique_id'] or str(uid), tag='SESSION ✓')
    ui.row('nickname', info['nickname'])
    ui.row('follower', info['follower_count'], 'following', info['following_count'])
    ui.row('video', info['aweme_count'], '❤ nhận', info['total_favorited'])
    ui.row('❤ đã thả', info['favoriting_count'], 'region', info['region'])
    ui.row('email', info['email'], 'password', 'có ✓' if info['has_password'] else '—')
    ui.row('uid', uid)
    ui.box_bot()
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, f'{uid}.json'), 'w', encoding='utf-8') as f:
            json.dump({**info, 'cookie': session.get('cookie'), 'ts': now_ms()}, f, ensure_ascii=False, indent=2)
        print(f"  (đã lưu out/{uid}.json)")
    except Exception:
        pass
    return info


def load_persist_device(user, fields):
    """Ưu tiên: device provided ở account.txt > device đã lưu (tái dùng) > None (chain sẽ register mới)."""
    did = fields[4] if len(fields) > 4 else ''
    iid = fields[5] if len(fields) > 5 else ''
    if did and iid:
        idn = {'openudid': fields[6] if len(fields) > 6 else '',
               'cdid': fields[7] if len(fields) > 7 else '',
               'google_aid': (fields[8] if len(fields) > 8 else '') or str(uuid.uuid4())}
        print(f'✓ 02 device (provided)   did={did} iid={iid}')
        return {'device_id': did, 'install_id': iid, 'id': idn}
    dev_file = os.path.join(DEV, safe_name(user) + '.json')
    if os.path.exists(dev_file):
        with open(dev_file, encoding='utf-8') as f:
            s = json.load(f)
        print(f"✓ 02 device (reuse)      did={s['device_id']} iid={s['install_id']} (giữ device riêng)")
        return {'device_id': s['device_id'], 'install_id': s['install_id'], 'id': s.get('id') or {}}
    return None


def save_persist_device(user, dev):
    try:
        os.makedirs(DEV, exist_ok=True)
        with open(os.path.join(DEV, safe_name(user) + '.json'), 'w', encoding='utf-8') as f:
            json.dump({'device_id': dev['device_id'], 'install_id': dev['install_id'],
                       'new_user': dev.get('new_user'), 'id': dev.get('id'), 'ts': now_ms()}, f)
    except Exception:
        pass


def main():
    line = os.environ.get('ACCOUNT') or (sys.argv[1] if len(sys.argv) > 1 else None)
    if not line or len(line.split('|')) < 2:
        print('cần ACCOUNT="user|pass|email|mailpass"')
        return 2
    fields = [x.strip() for x in line.split('|')]
    acc = parse_account(line)
    u = acc['username']
    ui.head(f'LOGIN  {u}')
    print(f"   {ui.DIM}signer={os.environ.get('SIGNER_URL') or os.environ.get('METASEC_ORACLE') or 'signer-bridge'}"
          f"  proxy={'ON' if os.environ.get('PROXY_URL') else 'off'}{ui.RESET}")

    dev = load_persist_device(u, fields)
    r = run_login_chain(acc, read_code=make_reader(acc), dev=dev)
    if dev is None and r.get('dev'):      # freshly registered → LƯU device để tái dùng
        save_persist_device(u, r['dev'])

    if not r['ok']:
        append_fail(u, r.get('step'), getattr(r.get('error', None), 'ec', ''))
        return finish(1)

    s = r['session']
    s['user'] = u
    show_info(s)

    # follow tùy chọn (write-op)
    target = os.environ.get('FOLLOW')
    if target and r.get('dev') and r.get('d'):
        fr = follow_mod.follow_and_verify(r['dev'], r['d'], target, s.get('xtt', ''),
                                          cookie=s.get('cookie'), type=os.environ.get('FOLLOW_TYPE', '1'))
        if fr.get('ok'):
            v = fr['verdict']
            tag = (f"{ui.GREEN}✅ STUCK (follow thật){ui.RESET}" if v == 'stuck'
                   else (f"{ui.YELLOW}⚠️ shadow-drop{ui.RESET}" if v == 'shadow' else v))
            print(f"\n{ui.CYAN}➤ FOLLOW{ui.RESET} @{fr['target']}: sc={fr['follow_sc']} "
                  f"follow_status {fr['follow_status_before']}→{fr['follow_status_after']} → {tag}")
        else:
            print(f"\n{ui.CYAN}➤ FOLLOW{ui.RESET} @{target}: {ui.YELLOW}{fr.get('reason', 'fail')}{ui.RESET}")

    # lưu session tùy chọn
    sp = os.environ.get('SAVE_SESSION')
    if sp and r.get('dev') and r.get('d'):
        try:
            sess_mod.save_session(s, r['dev'], r['d'], sp)
            print(f'  (đã lưu session → {sp})')
        except Exception as e:
            print(f'  (lưu session lỗi: {e})')
    return finish(0)


if __name__ == '__main__':
    sys.exit(main())
