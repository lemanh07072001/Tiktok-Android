"""re/py/ui.py — màu + box cho console (tự bật ANSI trên Windows cmd). Dùng chung chain/worker.
Tắt màu: đặt env NO_COLOR=1.
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def _enable_ansi():
    if os.name == 'nt':
        try:
            import ctypes
            h = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode))
            ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 0x0004)  # VT processing
        except Exception:
            pass


_enable_ansi()
_ON = os.environ.get('NO_COLOR') is None


def _c(code):
    return code if _ON else ''


GREEN = _c('\033[92m')
RED = _c('\033[91m')
CYAN = _c('\033[96m')
YELLOW = _c('\033[93m')
DIM = _c('\033[90m')
BOLD = _c('\033[1m')
RESET = _c('\033[0m')
W = 52   # bề rộng box (ký tự)


def ok(step, detail=''):
    print(f'{GREEN}✓{RESET} {BOLD}{step}{RESET}' + (f'   {DIM}{detail}{RESET}' if detail else ''), flush=True)


def fail(text):
    print(f'{RED}{text}{RESET}', flush=True)


def head(title):
    print(f'\n{CYAN}{"─" * W}{RESET}\n {BOLD}{title}{RESET}\n{CYAN}{"─" * W}{RESET}', flush=True)


def box_top(title, tag=''):
    tagstr = f' {GREEN}{BOLD}{tag}{RESET}{CYAN} ' if tag else ' '
    left = f'┌── {BOLD}{title}{RESET}{CYAN} ──{tagstr}'
    fill = max(3, W - len(title) - len(tag) - 12)
    print(f'{CYAN}{left}{"─" * fill}{RESET}', flush=True)


def row(label, value, label2='', value2=''):
    val = '—' if value in (None, '') else str(value)
    line = f'{CYAN}│{RESET}  {DIM}{label:<12}{RESET}{BOLD}{val}{RESET}'
    if label2:
        pad = max(2, 26 - 14 - len(val))
        v2 = '—' if value2 in (None, '') else str(value2)
        line += ' ' * pad + f'{DIM}{label2:<11}{RESET}{v2}'
    print(line, flush=True)


def box_bot():
    print(f'{CYAN}└{"─" * (W - 1)}{RESET}', flush=True)
