# Track A Hybrid A2 — Practical slot16 Offline via Phone-Oracle

> Phiên dài: execute không progress report. Chỉ báo cuối phiên.

**Goal:** Implement practical slot16 signer: login 1x → capture slot16/request live → reuse offline cho multiple requests.

**Approach:** Reuse slot16_capture.js (note 33, proven 30 obs) + build runner to extract + replay slot16 for any query.

**Output:** `compute_slot16_hybrid.py` — takes captured slot16 dict + new query → returns matching slot16 (or computes if same class).

---

## Phase H1: Understand Captured slot16 Data

### Task H1.1: Load & analyze slot16 data from note 33
- Read slot16_newphone_verified.json (30 obs + 4 nonzero slot16)
- Identify patterns: query_class → slot16_value mapping
- Group by query_class (device_platform vs content API)
- Check: is slot16 deterministic per (query_class, device_id, keva)?

### Task H1.2: Verify slot16 determinism via clean tuples
- Load _clean_tuples.json (3 same-keva tuples, diff _rticket)
- If slot16 varies only by _rticket (not device/PSK) → session-level determinism
- Hypothesis: slot16 = f(_rticket, ts) + PSK session context

---

## Phase H2: Build slot16 Capture Runner

### Task H2.1: Implement slot16_capture_runner.py
- Mimic slot16_capture.js logic in Python
- Input: A1 capture state + query parameters
- Output: predicted slot16 (from regfile state machine)
- Test: match vs captured clean tuples

### Task H2.2: Test vs 3 clean tuples
- For each tuple (different _rticket):
  - Feed query + keva to runner
  - Get predicted slot16
  - Compare vs expected (from _clean_tuples.json)
- Success: 3/3 match
- Failure: analyze divergence (missing state variable, computation order)

---

## Phase H3: Implement Final Hybrid Signer

### Task H3.1: compute_slot16_hybrid.py
- API: `compute_slot16_hybrid(psk, keva, device_id, captured_slot16_dict, query) -> slot16_hex`
- Lookup captured_slot16_dict for same query class
- If found → return directly
- If not found → compute via runner (if applicable to query_class)

### Task H3.2: Integration test
- Mock TikTok login session (PSK + keva provisioned)
- Capture slot16 for device_register (nonzero) + content API (zero)
- Use hybrid signer to sign 10 different requests:
  - 5x device_register (reuse captured)
  - 5x content API (use zero, compute #19)
- Verify: all signatures valid (no phone needed)

---

## Success Criteria
- 3/3 clean tuples match
- Hybrid signer API working
- Integration test 10/10 requests sign correctly
- No phone required after initial capture

---

## Timeline: Same session (4-6 hours)
