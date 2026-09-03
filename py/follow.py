"""re/py/follow.py — write-op FOLLOW: search sec_uid → commit follow → verify stick. Port re/tests/*.mjs.
⚠️ Follow chỉ "lên thật" trên session SẠCH (signup non-2135). Session 2135-recovery → server nhận GIẢ
   (status_code=0, follow_status=1) nhưng re-search follow_status về 0 = shadow-drop (đã chứng minh).
"""
import time

from errors import SESSION
import login
from net import now_ms

AWEME_HOST = 'api22-normal-c-alisg.tiktokv.com'   # aweme normal (search + write)


def _cdid(dev):
    return (dev.get('id') or {}).get('cdid') or dev.get('cdid') or ''


def search_user(dev, d, keyword, xtt, cookie=None, count=10):
    """GET /aweme/v1/discover/search/ → resolve user. cookie=None → dùng JAR (login same-process)."""
    keyword = keyword.lstrip('@')
    r = login.passport_call(
        dev, d, '/aweme/v1/discover/search/', method='GET', host=AWEME_HOST,
        extra_query={'keyword': keyword, 'count': str(count), 'offset': '0',
                     'search_source': 'normal_search', 'type': '1', 'cdid': _cdid(dev)},
        tt_token=xtt, drop_dg=True, cookie_override=cookie, step='search', layer=SESSION)
    ul = (r['j'] or {}).get('user_list') or []
    hit = None
    for it in ul:
        ui = it.get('user_info') or {}
        if (ui.get('unique_id') or '').lower() == keyword.lower():
            hit = ui
            break
    if hit is None and ul:
        hit = ul[0].get('user_info') or {}
    info = None
    if hit:
        info = {'uid': hit.get('uid'), 'sec_uid': hit.get('sec_uid'),
                'follow_status': hit.get('follow_status'), 'follower_count': hit.get('follower_count'),
                'nickname': hit.get('nickname'), 'unique_id': hit.get('unique_id')}
    return {'status_code': (r['j'] or {}).get('status_code'), 'hit': info, 'raw': r}


def follow_user(dev, d, uid, sec_uid, xtt, cookie=None, type='1'):
    """POST /aweme/v1/commit/follow/user/ (ticket-guard write-op). type 1=follow, 0=unfollow."""
    params = {'user_id': str(uid), 'sec_user_id': sec_uid, 'type': str(type), 'channel_id': '0',
              'from': '19', 'from_pre': '0', 'previous_page': '', 'action_time': str(now_ms()),
              'is_network_available': 'true'}
    r = login.passport_call(
        dev, d, '/aweme/v1/commit/follow/user/', method='POST', host=AWEME_HOST,
        params=params, extra_query={'cdid': _cdid(dev)}, tt_token=xtt,
        keep_tg=True, drop_dg=True, cookie_override=cookie, step='follow', layer=SESSION)
    j = r['j'] or {}
    return {'status_code': j.get('status_code'), 'follow_status': j.get('follow_status'),
            'watch_status': j.get('watch_status'), 'raw': j}


def follow_and_verify(dev, d, keyword, xtt, cookie=None, type='1', wait=4.0):
    """Full: search → follow → chờ → re-search follow_status → verdict STUCK/shadow/fail."""
    keyword = keyword.lstrip('@')
    s = search_user(dev, d, keyword, xtt, cookie=cookie)
    hit = s['hit']
    if not hit or not hit.get('uid') or not hit.get('sec_uid'):
        return {'ok': False, 'reason': 'no_sec_uid', 'search': s}
    before = hit.get('follow_status')
    fr = follow_user(dev, d, hit['uid'], hit['sec_uid'], xtt, cookie=cookie, type=type)
    time.sleep(wait)
    after_s = search_user(dev, d, keyword, xtt, cookie=cookie)
    after = (after_s['hit'] or {}).get('follow_status')
    verdict = 'stuck' if after == 1 else ('shadow' if fr['status_code'] == 0 else 'fail')
    return {'ok': fr['status_code'] == 0, 'target': keyword, 'uid': hit['uid'],
            'follow_status_before': before, 'follow_sc': fr['status_code'],
            'follow_status_after': after, 'follower_count': (after_s['hit'] or {}).get('follower_count'),
            'verdict': verdict, 'follow': fr}
