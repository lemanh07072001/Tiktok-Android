#!/usr/bin/env bash
# Turnkey: chạy Ghidra headless để khoanh vùng slot16 producer.
# Không cần cài gì thêm — JDK + Ghidra đã ở ~/tools (portable, no sudo).
set -euo pipefail

export JAVA_HOME="$HOME/tools/jdk-21.0.12.1+1/Contents/Home"
GHIDRA="$HOME/tools/ghidra_12.1.3_PUBLIC"
HEADLESS="$GHIDRA/support/analyzeHeadless"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SO="$REPO/huongB_devirt19/bin/libmetasec_ov.so"
PROJDIR="$HOME/tools/ghidra_proj"
mkdir -p "$PROJDIR"

if [[ ! -x "$HEADLESS" ]]; then
  echo "!! Chưa thấy $HEADLESS — Ghidra chưa giải nén xong?"; exit 1
fi
if [[ ! -f "$SO" ]]; then
  echo "!! Không thấy .so: $SO"; exit 1
fi

echo "== JAVA_HOME=$JAVA_HOME"
echo "== Ghidra=$GHIDRA"
echo "== import=$SO"
echo "== (lần đầu sẽ auto-analyze ~1-3 phút cho 2MB ARM64) =="

# Nếu program đã import (project tt có sẵn) -> -process (KHÔNG analyze lại, nhanh).
# Lần đầu -> -import. Java script không cần PyGhidra.
if [[ -f "$PROJDIR/tt.rep/idata/~index.dat" || -d "$PROJDIR/tt.rep" ]]; then
  echo "== program đã import, dùng -process (bỏ qua analyze) =="
  "$HEADLESS" "$PROJDIR" tt \
    -process libmetasec_ov.so -noanalysis \
    -scriptPath "$REPO/huongB_devirt19" \
    -postScript GhidraFindSlot16.java
else
  "$HEADLESS" "$PROJDIR" tt \
    -import "$SO" -overwrite \
    -scriptPath "$REPO/huongB_devirt19" \
    -postScript GhidraFindSlot16.java
fi

echo ""
echo "== XONG. Đọc kết quả decompile tại: huongB_devirt19/_ghidra_out/fn_*.c =="
echo "== Bảng RANK hash-hint in ở trên; hàm hash-hint cao nhất = ứng viên producer =="
