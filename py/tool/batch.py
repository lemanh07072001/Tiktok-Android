"""re/py/tool/batch.py — LAUNCHER: đọc account.txt + proxy.txt (+ config.txt), chạy MỖI account 1 tiến trình
   worker.py riêng, mỗi tiến trình 1 PROXY_URL. Port re/tool/batch.mjs.
  python batch.py            # Windows: mở CỬA SỔ console mới mỗi account (worker tự pause giữ cửa sổ)
  python batch.py --headless # chạy nền, không mở cửa sổ (in-line, worker NO_PAUSE)
  python batch.py --dry      # chỉ in kế hoạch ghép account↔proxy
"""
import os
import re
import sys
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

WORKER = os.path.join(HERE, 'worker.py')


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8') as f:
        return [x.strip() for x in f if x.strip() and not x.strip().startswith('#')]


def to_proxy(line):
    if '://' in line:
        return line
    a = line.split(':')
    if len(a) == 4:
        return f'http://{a[2]}:{a[3]}@{a[0]}:{a[1]}'
    if len(a) == 2:
        return f'http://{a[0]}:{a[1]}'
    return line


def read_config():
    cfg = {}
    for ln in read_lines(os.path.join(HERE, 'config.txt')):
        i = ln.find('=')
        if i > 0:
            cfg[ln[:i].strip()] = ln[i + 1:].strip()
    return cfg


def main():
    dry = '--dry' in sys.argv
    headless = '--headless' in sys.argv
    accounts = read_lines(os.path.join(HERE, 'account.txt'))
    proxies = [to_proxy(x) for x in read_lines(os.path.join(HERE, 'proxy.txt'))]
    cfg = read_config()
    stagger = int(cfg.get('STAGGER_MS', '1500')) / 1000.0
    signer = (os.environ.get('SIGNER_URL') or cfg.get('SIGNER_URL')
              or os.environ.get('METASEC_ORACLE') or cfg.get('METASEC_ORACLE') or '')

    if not accounts:
        print('⚠ account.txt trống — thêm mỗi dòng 1 account: user|pass|email|mailpass')
        return 2
    if not proxies:
        print('⚠ proxy.txt trống → chạy KHÔNG proxy (dễ dính ec7 velocity). Nên có IP sạch.')

    per_row = int(cfg.get('PER_ROW', '5'))
    tile_on = cfg.get('TILE', '1') != '0' and '--no-tile' not in sys.argv
    prefix = f'T{os.getpid()}_'   # scope tile theo run này
    print(f"── launcher(py): {len(accounts)} account · {len(proxies)} proxy · "
          f"signer={signer or '(SIGNER_URL chưa set!)'} · {per_row}/hàng · stagger={stagger}s {'(DRY)' if dry else ''}")

    for i, account in enumerate(accounts):
        user = account.split('|')[0]
        proxy = proxies[i % len(proxies)] if proxies else ''
        shown = re.sub(r'//[^@]*@', '//***@', proxy) or '(none)'
        print(f"  #{i + 1} {user}  ←  {shown}")
        if dry:
            continue
        env = {**os.environ, 'ACCOUNT': account}
        if proxy:
            env['PROXY_URL'] = proxy
        if signer:
            env['SIGNER_URL'] = signer
            env['METASEC_ORACLE'] = signer
        if cfg.get('RE_VER'):
            env['RE_VER'] = cfg['RE_VER']
        if cfg.get('OMO_API_KEY') and not env.get('OMO_API_KEY'):
            env['OMO_API_KEY'] = cfg['OMO_API_KEY']   # giải slide-captcha (ec1105/1108)
        if headless:
            env['NO_PAUSE'] = '1'
            subprocess.Popen([sys.executable, WORKER], env=env, cwd=HERE)
        elif os.name == 'nt':
            # MỞ CỬA SỔ MỚI qua `start` (HIỆN chắc chắn; Popen(CREATE_NEW_CONSOLE) đôi khi KHÔNG hiện).
            # TITLE = prefix+idx+user để tile.ps1 nhận & sắp xếp. cmd /k giữ cửa sổ mở.
            title = prefix + str(i + 1) + '_' + re.sub(r'[^A-Za-z0-9]', '_', user)[:28]
            wenv = {**env, 'NO_PAUSE': '1'}   # cmd /k đã giữ cửa sổ → worker khỏi pause
            inner = f'chcp 65001>nul&& "{sys.executable}" worker.py'
            subprocess.Popen(f'start "{title}" cmd /k "{inner}"', shell=True, env=wenv, cwd=HERE)
        else:
            subprocess.Popen([sys.executable, WORKER], env=env, cwd=HERE)
        time.sleep(stagger)

    # xếp lưới per_row cửa/hàng (chỉ cửa sổ của run này — prefix T<pid>_)
    if tile_on and not dry and not headless and os.name == 'nt':
        time.sleep(1.3)
        ps1 = os.path.join(HERE, 'tile.ps1')
        if os.path.exists(ps1):
            print(f'⊞ xếp cửa sổ {per_row}/hàng…')
            subprocess.Popen(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1,
                              '-PerRow', str(per_row), '-Prefix', prefix])

    print('\n(DRY) không chạy. Bỏ --dry để chạy thật.' if dry
          else f"\n✓ đã chạy {len(accounts)} account ({per_row}/hàng). Kết quả lưu re/py/tool/out/.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
