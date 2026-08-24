# Track B (Revised) — Phone Capture Full Bytecode Trace

**Goal**: Vào phone 1 lần → capture full VM bytecode execution trace → offline signer (never phone after that)

**Scope**: Login → trigger device_register request → hook 0x55890 dispatch → log every opcode + regfile mutation → extract to JSON → analyze offline

**Duration**: Same session, part 2 (phone work ~30min + offline analysis multi-hour)

---

## Phase P1: Prepare Capture Hook (Offline)

### Task P1.1: Update _a1_vmcap.js for FULL bytecode trace
- Current: hooks SM3@0xa0748, dumps regfile at entry
- Needed: hook 0x55890 (dispatch), log EVERY `br x15`, regfile after each opcode
- Output: `execution_trace.json` — list of {opcode, regfile_before, regfile_after, bytecode_ptr}

### Task P1.2: Write trace runner for phone
- Same format as _a1_vmcap.js (Frida-based)
- Target: single device_register request → full trace
- Upload to phone via adb

---

## Phase P2: Phone Capture (ON DEVICE)

### Task P2.1: Run trace hook on phone (manual steps for user)
```
1. adb push _a1_vmcap_full_trace.js /data/local/tmp/
2. frida -f com.zhiliaoapp.musically -l /data/local/tmp/_a1_vmcap_full_trace.js
3. Let app init ~30s (capture trace)
4. adb pull /data/local/tmp/execution_trace.json ./
5. Done — phone never needed again
```

### Task P2.2: Verify trace completeness
- Check: trace has >1000 opcodes (full execution, not truncated)
- Verify: regfile[29] mutations traced
- Extract key values: PSK (if visible), ratchet progression, output register

---

## Phase P3: Offline Signer Implementation (Multi-hour)

### Task P3.1: Analyze execution trace
- Parse trace JSON
- Identify opcode sequence (op44, op40, micro-ops, exit)
- Track regfile[29] (ratchet) progression step-by-step
- Identify input variables (device_id, query params) vs computed state

### Task P3.2: Reverse-engineer opcode semantics from trace
- For each opcode: trace input regfile → output regfile
- Identify pattern (ALU op? memory load? branch? XOR?)
- Build opcode lookup table

### Task P3.3: Implement offline VM simulator
- From regfile input → simulate opcode sequence → regfile output
- Test: simulate captured trace → verify regfile[29] final value matches

### Task P3.4: Extract & generalize slot16 formula
- From simulated regfile: which register holds slot16 output?
- Test on different query params: does formula generalize?
- Implement `compute_slot16_offline(psk, device_state, query) -> slot16`

### Task P3.5: Verification vs oracle
- Test on clean tuples (if applicable to same device)
- Verify offline computation matches captured trace

---

## Success Criteria
- Full bytecode trace captured (>1000 opcodes)
- Offline simulator matches trace (regfile bit-exact)
- slot16 formula extracted & generalized
- offline signer works: `compute_slot16(query) -> slot16` (no phone)

---

## Estimate
- Phone work: 30 min
- Offline analysis: 2-3 hours
- Total: 3-4 hours same session
