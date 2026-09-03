"""re/py/tool/check_follow.py — verify follow CÓ THẬT không (nạp session ĐÃ LƯU, KHÔNG re-login). Port t_check_follow.mjs.
  SESSION_FILE=sess.json TARGET=idmahg [PROXY_URL=...] python check_follow.py   (hoặc argv[1]=session file)
  [1] search target → follow_status (0=chưa,1=đang follow) + follower_count (server có ghi follow không)
  [2] self profile → following_count của account
  [3] re-follow → response follow_status
⚠️ follow_status về 0 sau khi follow = shadow-drop (session 2135-recovery). =1 giữ = STUCK (session sạch).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import net  # noqa: E402  (side-effect: proxy egress từ PROXY_URL)
import session as sess_mod  # noqa: E402
import follow as follow_mod  # noqa: E402


def main():
    path = os.environ.get('SESSION_FILE') or (sys.argv[1] if len(sys.argv) > 1 else None)
    target = (os.environ.get('TARGET') or 'idmahg').lstrip('@')
    if not path or not os.path.exists(path):
        print('cần SESSION_FILE=<path session.json> (hoặc argv[1])')
        return 2
    dev, d, s = sess_mod.load_session(path)
    xtt, cookie = s.get('xtt', ''), s.get('cookie', '')
    # call_authed cần device_id/iid ở top-level của session dict
    s['device_id'], s['iid'] = dev['device_id'], dev['install_id']
    print(f"== account {s.get('user')} user_id={s.get('user_id')} ==")

    # [1] search target → follow_status theo góc account này
    sr = follow_mod.search_user(dev, d, target, xtt, cookie=cookie)
    hit = sr['hit'] or {}
    print(f"[1] search sc={sr['status_code']} @{target} uid={hit.get('uid')} "
          f"follower_count={hit.get('follower_count')} follow_status={hit.get('follow_status')} (0=chưa,1=đang follow)")

    # [2] self profile → following_count
    try:
        prof = sess_mod.call_authed(s, '/aweme/v1/user/', extra_query={
            'user_id': s.get('user_id'), 'sec_user_id': s.get('sec_uid', ''), 'cdid': dev.get('cdid')})
        pj = prof.get('j') or {}
        self_u = pj.get('user') or {}
        print(f"[2] self sc={pj.get('status_code')} following_count={self_u.get('following_count')} "
              f"follower_count={self_u.get('follower_count')} aweme={self_u.get('aweme_count')}")
    except Exception as e:
        print(f"[2] self lỗi: {e}")

    # [3] re-follow → response
    if hit.get('uid') and hit.get('sec_uid'):
        fr = follow_mod.follow_user(dev, d, hit['uid'], hit['sec_uid'], xtt, cookie=cookie)
        print(f"[3] re-follow sc={fr['status_code']} follow_status={fr['follow_status']} watch_status={fr['watch_status']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
