"""re/py/tool/follow_flow.py — LUỒNG FOLLOW no-phone: mỗi account login(2135 full)→follow target→verify STUCK/shadow.
   Port re/tests/follow_flow.mjs. Spawn worker.py/tiến trình (mỗi account 1 PROXY_URL — net.py fix proxy theo process).
  python follow_flow.py <target> [type=1|0] [--acc accounts.txt] [--proxy proxies.txt] [--conc N]
    accounts.txt: mỗi dòng "user|pass|email|mailpass"
    proxies.txt : mỗi dòng "ip:port:user:pass"
"""
import os
import re
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

WORKER = os.path.join(HERE, 'worker.py')


def flag(name, default=None):
    a = sys.argv
    return a[a.index(name) + 1] if name in a and a.index(name) + 1 < len(a) else default


def to_proxy(line):
    if '://' in line:
        return line
    a = line.split(':')
    if len(a) == 4:
        return f'http://{a[2]}:{a[3]}@{a[0]}:{a[1]}'
    if len(a) == 2:
        return f'http://{a[0]}:{a[1]}'
    return line


def read_lines(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding='utf-8') as f:
        return [x.strip() for x in f if x.strip() and not x.strip().startswith('#')]


def run_one(idx, total, account, proxy, target, ftype):
    user = account.split('|')[0]
    env = {**os.environ, 'ACCOUNT': account, 'FOLLOW': target, 'FOLLOW_TYPE': ftype, 'NO_PAUSE': '1'}
    if proxy:
        env['PROXY_URL'] = proxy
    try:
        p = subprocess.run([sys.executable, WORKER, account], env=env, capture_output=True,
                           text=True, timeout=280, encoding='utf-8', errors='replace')
        out = (p.stdout or '') + (p.stderr or '')
    except subprocess.TimeoutExpired:
        out = '(timeout)'
    session = 'THÔNG TIN TÀI KHOẢN' in out
    uid = (re.search(r'uid\s*:\s*(\d+)', out) or [None, None])[1]
    m = re.search(r'FOLLOW @\S+: sc=(-?\d+) follow_status \d+→(\d+) → (.+)', out)
    if not session:
        ec = (re.search(r'ec=(\d+)', out) or [None, None])[1]
        status = 'ec7(throttle/IP)' if (ec == '7' or 'Maximum' in out) else f'login-fail({ec or "?"})'
        verdict = 'nologin'
    elif m:
        after = m.group(2)
        verdict = 'stuck' if after == '1' else ('shadow' if m.group(1) == '0' else 'fail')
        status = {'stuck': '✅ STUCK', 'shadow': '⚠️ shadow-drop'}.get(verdict, f'follow-{verdict}({m.group(1)})')
    else:
        status, verdict = 'session-ok/follow-?', 'unknown'
    proxy_show = proxy.split('@')[-1] if proxy else 'direct'
    print(f"  [{idx + 1}/{total}] {user} | {proxy_show} → {'SESSION ' + (uid or '') if session else 'NO-SESSION'} | follow: {status}", flush=True)
    return {'user': user, 'uid': uid, 'session': session, 'verdict': verdict, 'status': status}


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith('--'):
        print('cần <target>. VD: python follow_flow.py idmahg 1 --acc accounts.txt --proxy proxies.txt')
        return 2
    target = sys.argv[1].lstrip('@')
    ftype = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] in ('0', '1') else '1'
    accounts = read_lines(flag('--acc', os.path.join(HERE, 'accounts.txt')))
    proxies = [to_proxy(x) for x in read_lines(flag('--proxy', os.path.join(HERE, 'proxies.txt')))]
    conc = int(flag('--conc', '2'))
    if not accounts:
        print('accounts.txt trống (user|pass|email|mailpass mỗi dòng)')
        return 2
    print(f"[follow_flow] {len(accounts)} account → follow @{target} (type={ftype}) | {len(proxies)} proxy | conc={conc}")

    results = [None] * len(accounts)
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = {ex.submit(run_one, i, len(accounts), a, (proxies[i % len(proxies)] if proxies else ''),
                          target, ftype): i for i, a in enumerate(accounts)}
        for fut in futs:
            i = futs[fut]
            results[i] = fut.result()

    stuck = sum(1 for r in results if r and r['verdict'] == 'stuck')
    shadow = sum(1 for r in results if r and r['verdict'] == 'shadow')
    nologin = sum(1 for r in results if r and not r['session'])
    print(f"\n===== TỔNG KẾT follow @{target} =====")
    print(f"✅ STUCK (follow thật): {stuck}/{len(results)}  |  ⚠️ shadow-drop: {shadow}  |  ❌ no-session: {nologin}")
    for r in results:
        if r:
            print(f"  {r['user']} → {r['status']}" + (f" (uid {r['uid']})" if r['uid'] else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
