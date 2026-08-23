# slot16 computation — analysis & plan (2026-08-23)

## Key finding: this is a Pitaya VM bytecode interpreter

The VM at 0x55950 executes Pitaya bytecode (libAndroidPitayaCore.so).
The bytecode at 0x17bc6c-0x194dac (102,728 bytes) is a COMPLETE Pitaya program
containing string tables, device info collection, PSK state management,
and request signing logic. The Pitaya C API (PTY*) is called by the VM handlers.

**Why device-register can be signed offline:**
- Device-register is the FIRST request — no PSK state exists yet
- slot16 for device-register must be computed from device info + embedded secrets
- The .msp files are CREATED by device-register, not consumed by it
- Therefore: slot16(device-register) = f(device_info, request_params, embedded_key)

## Bytecode structure

### Format
Each entry: [header:4B=0x003f956c] [opword:4B] [data_slots:N*8B]

### Opcode frequency (from exec_trace.json, 639 ops)
| Op | Count | Data slots | Handler | Role |
|----|-------|-----------|---------|------|
| 18 | 240x  | 0-806     | 0x5ad2c | Computation (202 small) + Data def (38 large) |
| 38 | 148x  | 2-90      | 0x58a54 | Micro-op: float/double/int compare |
| 15 | 111x  | 3-10      | 0x59714 | Micro-op: sign-extend/load/store |
| 40 | 38x   | 3-3420    | 0x5b7e4 | Data blocks (encrypted bytecode) |
| 1  | 30x   | 4-42      | 0x59518 | Control flow / state transition |
| 63 | 23x   | 3-186     | 0x5b9b0 | Unknown |
| 44 | 19x   | 3-118     | 0x52b4c | Bytecode pointer advance |

### Data blocks
- op=18 large entries: string tables (METASEC, mssdk, device fields, URLs, Pitaya API)
- op=40 entry at 0x188a88: 27,360 bytes ENCRYPTED (256/256 unique bytes, high entropy)
- Embedded bytecode references: patterns like 0x003f956c (header), 0x...06d2 (op=18)

## Two paths to offline slot16

### Path A: Compute device-register slot16 (no PSK needed)
1. Identify the device-register specific bytecode path
2. The slot16 = f(device_info, request_params, embedded_key)
3. Embedded key is in the SO (static, not runtime-derived)
4. Extract the algorithm from the VM bytecode
5. Implement in Python

### Path B: Extract PSK plaintext (for all requests)
1. Use unidbg to decrypt .msp files (proven to work, note 34)
2. Feed PSK plaintext + request data into VM
3. Implement VM lifter for slot16 computation
4. Works for ANY request, not just device-register

## Recommended next step: Path A first

Path A is simpler because:
- No unidbg dependency
- No .msp decryption needed
- Device-register is the only request that needs nonzero slot16
- All other requests use slot16=0 (already solved)

## Tools built
- `_slot16_trace.py` — Full bytecode decoder, data slot analysis, string extraction
- `_vm_unicorn_v2.py` — Unicorn emulation harness (working for atomic_capture bytecode)
- `_vm_lifter.py` — Python VM lifter (5 opcodes stubbed, needs implementation)

## Files
- `exec_trace.json` — 639 opcodes from live slot16 computation
- `captured_data.json` — 40 VM state captures (different bytecode, same session)
- `psk_files/` — 11 encrypted PSK state files (.msp, .msf3, .mss)
- `sign_bytecode.bin` — 103,316 bytes of VM bytecode