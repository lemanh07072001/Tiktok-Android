# Track B: Never-Phone Signer — User Guide

**Mục tiêu**: Ký offline sau khi capture dữ liệu 1 lần trên phone.

---

## Step 1: Chuẩn bị (Offline)

Tất cả đã sẵn sàng:
- `p1_full_trace_hook.js` — Frida capture hook
- `p3_offline_signer.py` — Signer template (sẽ fill handlers)
- `p3_analyze_trace.py` — Trace analyzer

## Step 2: Vào Phone Capture (~30 phút)

```bash
# Push hook
adb push scratchpad/p1_full_trace_hook.js /data/local/tmp/

# Launch app với trace hook
frida -f com.zhiliaoapp.musically -l /data/local/tmp/p1_full_trace_hook.js

# Let app run ~30s (init window, SM3 trigger device_register)
# Watch Frida output:
#   [*] SM3 entry — starting trace
#   [D#100] op40
#   [D#200] op40
#   ...
#   [+] Trace saved to /data/local/tmp/execution_trace.json

# Pull trace
adb pull /data/local/tmp/execution_trace.json huongB_devirt19/

# DONE — phone never needed again
```

## Step 3: Offline Analysis & Implementation

```bash
# Analyze trace
python scratchpad/p3_analyze_trace.py

# Output shows:
#   - Opcode patterns
#   - Ratchet progression (qword[29])
#   - Formula hints

# Fill p3_offline_signer.py opcode handlers based on patterns
# Run test:
python scratchpad/p3_offline_signer.py

# Expected: compute_slot16_offline(psk, device_state, query) returns valid slot16
```

## Step 4: Verify on Clean Tuples

```python
from scratchpad.p3_offline_signer import compute_slot16_offline

psk = "c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163"
device_state = {"device_id": "7666223875861513749", "ratchet": 0x9d3450fc}

for tuple in clean_tuples:
    query = f"device_platform=android&os=android&ssmix=a&_rticket={tuple['_rticket']}"
    predicted = compute_slot16_offline(psk, device_state, query)
    expected = tuple['slot16']
    
    assert predicted == expected, f"Mismatch: {predicted} != {expected}"
```

## Current Status

- ✅ Capture hook ready
- ✅ Analyzer ready  
- ✅ Signer template ready
- ✅ Synthetic trace tested (opcode patterns verified)
- ⏳ Waiting: real phone trace (Step 2)
- ⏳ Next: fill handlers (Step 3) → test on clean tuples (Step 4)

---

## Files to Transfer to Phone

- `scratchpad/p1_full_trace_hook.js` (copy to phone via adb)

## Files to Use Offline

- `scratchpad/p3_analyze_trace.py` (run after pulling trace)
- `scratchpad/p3_offline_signer.py` (fill handlers, test)

---

**When phone trace arrives**: Run p3_analyze_trace.py → identify opcode semantics → fill p3_offline_signer.py → test → done.
