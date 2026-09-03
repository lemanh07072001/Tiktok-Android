export const meta = {
  name: 'lift-slot16-VM',
  description: 'Reverse VM opcodes op18/op42/op44 and build a Python lifter that computes slot16=F(PSK,seed), verified vs 13 pairs',
  phases: [
    { title: 'ReverseOps', detail: 'reverse op18/op42/op44 handlers into Python (validated vs trace regfile deltas)' },
    { title: 'Lift', detail: 'assemble interpreter for program 0x191f40, run on 13 pairs' },
    { title: 'Verify', detail: 'independent bit-exact check' },
  ],
}

const CTX = `
CONTEXT — Lift the Pitaya VM to compute slot16 = F(PSK, seed) offline (TikTok X-Argus).
Working dir = repo root. Files under huongB_devirt19/:
- bin/libmetasec_ov.so  (ARM64; disassemble with capstone + pyelftools; PT_LOAD vaddr==fileoff for .text).
- _vm_trace.jsonl  — GROUND-TRUTH execution trace of F's program (0x191f40), 786 lines, straight-line
  (all distinct pc). Each line: {"pc": bytecode-offset hex, "word": decrypted 32-bit VM instruction hex,
  "op": word & 0x3f, "rf": 256-byte regfile hex = 32 little-endian qwords, state BEFORE this instruction}.
  ALSO "stk": 256-byte hex = 32 little-endian qwords at SP (the interpreter scratch frame; e.g. op42 writes
  its result to sp+0x70 == stk[14]). So the FULL VM state per instruction = rf (x24 regfile) + stk (sp window).
  The DELTA between consecutive (rf,stk) snapshots reveals exactly what each instruction did.
  Observed: op42 writes stk[14] (sp+0x70); reg-file often unchanged — op42/op18 cooperate (op42 computes a
  value/address into scratch, a following op moves/uses it). Reverse them TOGETHER using rf+stk deltas.
  NOTE: this trace came from a unicorn run where 2 external C++ call-outs were stubbed to 0, so absolute DATA
  values may be off, but the OPCODE SEMANTICS (which regs read, operation, which reg written) are valid and
  fully determinable from rf-deltas + the handler disassembly.
- _corr_data.json — 13 GOLDEN rows {seed(4B hex), slot16(16B hex), rticket}; PSK constant across all =
  c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163 (32B).
- _singleshot.json — captured F entry: entry.regs (x0=prog 0x191f40, x1=inbuf ptr, x2/x3=tables, x4=outbuf),
  entry.regfile (initial 32-qword regfile hex), entry.mem (page dumps), entry.soData (runtime .data tables).
- _F_localization.md — full prior findings.
VM facts (verified): interpreter entry 0x52924; dispatch opcode = (*pc)&0x3f; handler = table1[op]-0x9b374,
table1@0x1d9488. Each handler: x23 holds ptr-to-current-bytecode-ptr; reads the 32-bit instruction word,
advances pc+=4, then SELF-DECRYPTS the next word (*(pc+4) ^= per-handler-key). 32-register file at x24
(8 bytes/reg, index<<3). Register-index fields are SCATTERED across the instruction-word bits
(e.g. src=word>>27; dst=((word>>22)&0x10)|((word>>7)&0xf); op42/op18 gather more indices via ubfx/bfxil).
Program 0x191f40 uses ONLY 3 opcodes: op18 (0x12, handler 0x5ad2c, appears 366x), op42 (0x2a, handler
0x5c0fc, 346x — the main ARX crypto op, reads TWO regfile slots [x24,idx1],[x24,idx2]), op44 (0x2c, handler
0x52b4c, 74x — computed control-flow: subop=(word>>6)&0x3f, br table2[subop]-0x9b374, table2@0x1d9688).
0 S-boxes in binary => ARX (Simon/Speck-family) operations only (add/xor/rotate/shift, 32- or 64-bit words).
Python: python3 with capstone, elftools, gmssl, Crypto installed.
Your final output IS structured data (a tool call). Ground every claim in the disasm + the trace; run code.`;

const OP_SCHEMA = {
  type: 'object',
  properties: {
    opcode: { type: 'integer' },
    handler_addr: { type: 'string' },
    operand_decode: { type: 'string', description: 'exact bit-field extraction of register indices / immediates from the 32-bit word' },
    operation: { type: 'string', description: 'precise operation on the regfile (which slots read, the ARX/logic op, which slot written), word size' },
    python_fn: { type: 'string', description: 'complete Python function def handler(word, reg): ... mutating the 32-int reg list; must be runnable' },
    validated: { type: 'boolean', description: 'true if verified against >=5 trace rf-delta examples' },
    validation_note: { type: 'string' },
  },
  required: ['opcode','operation','python_fn','validated'],
};
const LIFT_SCHEMA = {
  type: 'object',
  properties: {
    wrote_file: { type: 'string' },
    approach: { type: 'string' },
    matched_pairs: { type: 'integer' },
    total_pairs: { type: 'integer' },
    success: { type: 'boolean' },
    formula_summary: { type: 'string' },
    blocker: { type: 'string', description: 'if not solved, the precise remaining discrepancy' },
  },
  required: ['matched_pairs','total_pairs','success'],
};
const VERIFY_SCHEMA = {
  type: 'object',
  properties: { reproduced: { type: 'boolean' }, independent_note: { type: 'string' }, verdict: { type: 'string', enum: ['CONFIRMED','REFUTED','INCONCLUSIVE'] } },
  required: ['reproduced','verdict'],
};

phase('ReverseOps')
const ops = [
  { op:42, h:'0x5c0fc', note:'MAIN ARX crypto op (reads two regfile slots, does add/xor/rotate). Reverse the full bit-field operand decode AND the exact word-size ARX operation + destination. Validate the operation against >=8 consecutive rf-delta examples from _vm_trace.jsonl (find lines with op==42, diff rf before/after).' },
  { op:18, h:'0x5ad2c', note:'compute op (366x). It has a preamble of opaque-predicate math (mov/movk/cmp/b.lo) that is dead-code obfuscation — the REAL work starts ~0x5ad80 (ldr w16,[x16]; bit-field decode; regfile read/write). Reverse the real operation + operand decode. Validate vs >=8 rf-delta examples.' },
  { op:44, h:'0x52b4c', note:'computed control-flow (74x): subop=(word>>6)&0x3f; br table2[subop]-0x9b374 (table2@0x1d9688). Determine what the sub-handlers do (they may be no-op/advance/branch). For a straight-line trace, characterize how op44 affects pc/flow and whether it touches the regfile. Validate vs trace.' },
];
const reversed = await parallel(ops.map(o => () =>
  agent(`${CTX}\n\nTASK: Fully reverse VM opcode op${o.op} (handler ${o.h}). ${o.note}\nDisassemble the handler in bin/libmetasec_ov.so (capstone). Decode how the 32-bit instruction word yields register indices/immediates. Determine the exact operation on the 32-qword regfile (word size 32 vs 64, and the ARX/logic op). Write a runnable Python \`def op${o.op}(word, reg):\` that mutates a 32-int register list. VALIDATE it by replaying it against the rf snapshots in _vm_trace.jsonl for lines with op==${o.op}: apply your fn to rf[i] and check it produces rf[i+1]'s changed slot. Report match count.`,
    { label:`op${o.op}`, phase:'ReverseOps', schema:OP_SCHEMA, effort:'high' })));

phase('Lift')
const opsTxt = reversed.filter(Boolean).map(r => `op${r.opcode} validated=${r.validated} :: ${r.operation}\nPYFN:\n${r.python_fn}\nnote:${r.validation_note||''}`).join('\n\n---\n');
const lift = await agent(
  `${CTX}\n\nYou are the LIFT step. The reversed opcode handlers (validated vs trace):\n\n${opsTxt}\n\nTASK: Build huongB_devirt19/compute_slot16.py implementing the VM interpreter for program 0x191f40:\n1. Parse the program's instruction stream. Easiest: replay the exact op/word SEQUENCE from _vm_trace.jsonl (straight-line, 786 instrs) applying the reversed handlers to a register file. This sidesteps re-implementing the self-decrypt/dispatch.\n2. Initialize the register file from the captured initial state (_singleshot.json entry.regfile) BUT with PSK+seed substituted so it generalizes: determine where PSK (32B) and seed (4B) enter the regfile/inbuf by comparing entry.regfile & entry.mem to the known PSK and the captured seed. \n3. Run the 786-instruction sequence; extract the 16-byte slot16 from the final state (the output buffer / a specific regfile region — cross-check against where the trace writes the result).\n4. TEST against all 13 rows of _corr_data.json (set PSK + each seed, run, compare to slot16).\nIf the 2 stubbed call-outs injected data the crypto needs, identify it from the trace (the rf slots that appear from nowhere) and model them as fixed constants derived from PSK/seed. Iterate. Report matched_pairs/total and the file. Run everything yourself.`,
  { label:'lift', phase:'Lift', schema:LIFT_SCHEMA, effort:'high' });

phase('Verify')
let verify = null;
if (lift && lift.success) {
  verify = await agent(`${CTX}\n\nClaim: compute_slot16.py solves F, matched ${lift.matched_pairs}/${lift.total_pairs}. Independently re-run it against all 13 rows of _corr_data.json and confirm bit-exact. Verdict CONFIRMED only if all 13 match.`,
    { label:'verify', phase:'Verify', schema:VERIFY_SCHEMA, effort:'high' });
}
return { solved: !!(lift && lift.success), lift, verify, reversed: reversed.filter(Boolean).map(r=>({op:r.opcode,validated:r.validated})) };
