export const meta = {
  name: 'crack-slot16-F',
  description: 'Devirt/cryptanalyze the Pitaya VM to recover F(PSK,seed)->slot16 offline, verified vs 13 golden pairs',
  phases: [
    { title: 'Recon', detail: 'disasm B-program + VM handlers + fingerprint primitive (parallel)' },
    { title: 'Cryptanalysis', detail: 'attack 13 golden pairs by cipher family (parallel)' },
    { title: 'Synthesize', detail: 'combine into compute_slot16.py + test' },
    { title: 'Verify', detail: 'adversarial re-test of any claimed match' },
  ],
}

// ---- shared context embedded in every agent prompt (agents start fresh, no memory) ----
const CTX = `
CONTEXT (TikTok Android X-Argus offline signer — crack slot16 producer F):
- Repo root is the working dir. Key files under huongB_devirt19/:
  * bin/libmetasec_ov.so  (ARM64 shared lib, the target binary; disassemble with capstone + pyelftools for PT_LOAD vaddr->fileoff mapping)
  * _corr_data.json = 13 GOLDEN rows {seed (4B hex), slot16 (16B hex), rticket}. PSK is CONSTANT across all rows:
    PSK = c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163  (32 bytes)
  * sign_bytecode.bin (103KB VM bytecode), notes/40-slot16-characterization-DEFINITIVE.md, huongB_devirt19/slot16_findings.md
- GOAL: find F such that F(PSK, seed)==slot16 for ALL 13 rows (seed may be a DIRECT input OR an internal index/counter — try both).
- Python: run via  python3  (or "/c/Program Files/Python311/python.exe"). Installed: capstone, elftools (pyelftools), gmssl (SM3), Crypto (pycryptodome).
- HARD FACT — slot16 is DETERMINISTIC: wiping the on-disk .msp cache then cold-starting reproduces the EXACT same slot16 pool. So F is a pure function of PSK (device-stable) + an index; no fresh entropy, no server round-trip.
- ALREADY EXHAUSTIVELY TESTED AND FAILED (do NOT waste time re-testing these): standard MD5/SHA1/SHA256/SM3/HMAC in all argument orders; AES-128 and AES-256 ECB/CBC/CTR with every embedded key and every seed-block expansion; SM3/AES-CTR keystreams (36k blocks); hash-chains/ratchets; SM3 preimage capture (275 live messages) and SM3 output-state capture (1099 states). None reproduce slot16.
- STRONG LEAD: this SDK provably uses the SIMON lightweight block cipher (the X-Argus envelope inner layer is a Simon forward-Feistel). So Simon/Speck/other ARX-Feistel lightweight ciphers are prime suspects for F.
- VM facts: interpreter entry 0x52924; dispatch 'br' ~0x55890; operand XOR key 0x6a9091b9; predicate/dispatch-bias 0x9b374; op40 ratchet handler 0x5b8fc (pointer XOR 0xa123f43, byte ^0xed self-modifying); SM3 fn 0xa0748; MD5 0x15b594; SHA1 0x15bb00.
- F is invoked via the VM call at BL 0x1384e4 (return site 0x1384e8): the call site at 0x1384cc-0x1384e4 sets x0/x2/x3 = adrp+add pointers selecting the bytecode program + constant tables, x1/x4 = output buffers. A parallel producer at BL 0x10ac80 returns a 4-byte int (likely the index/counter generator). The giant report-assembly is BL 0x9fd70 (NOT F).
- Embedded key material: .data @0x960 (5x16B), .rodata @0x17baa0 (2x16B), 32B key @0x19b520 = 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b.
Your final output IS structured data (a tool call), not prose to a human. Ground every claim in the binary or the 13 pairs — run code, do not speculate.`;

const RECON_SCHEMA = {
  type: 'object',
  properties: {
    area: { type: 'string' },
    summary: { type: 'string', description: 'what this code region does, grounded in disasm' },
    key_findings: { type: 'array', items: { type: 'string' } },
    addresses: { type: 'array', items: { type: 'string' }, description: 'notable addresses/offsets found' },
    primitive_candidates: { type: 'array', items: { type: 'string' }, description: 'crypto primitives this suggests (e.g. simon64/128, aes, sm4, custom-arx)' },
    constants_or_tables: { type: 'array', items: { type: 'string' }, description: 'hex constants / table offsets relevant to F' },
    python_sketch: { type: 'string', description: 'python pseudocode of the operation if determinable' },
    confidence: { type: 'string', enum: ['low','medium','high'] },
  },
  required: ['area','summary','key_findings','primitive_candidates','confidence'],
};

const CRYPT_SCHEMA = {
  type: 'object',
  properties: {
    family: { type: 'string' },
    constructions_tested: { type: 'array', items: { type: 'string' } },
    matched: { type: 'boolean', description: 'true only if a construction reproduces ALL 13 pairs' },
    match_formula: { type: 'string', description: 'exact formula + params if matched, else empty' },
    partial_hits: { type: 'string', description: 'any construction matching some pairs / structural clue' },
    ruled_out: { type: 'array', items: { type: 'string' } },
    notes: { type: 'string' },
  },
  required: ['family','constructions_tested','matched','notes'],
};

const SYNTH_SCHEMA = {
  type: 'object',
  properties: {
    hypothesis: { type: 'string' },
    wrote_file: { type: 'string', description: 'path to compute_slot16.py if written' },
    matched_pairs: { type: 'integer' },
    total_pairs: { type: 'integer' },
    formula: { type: 'string' },
    success: { type: 'boolean' },
    next_lead: { type: 'string', description: 'if not solved, the single most promising next step' },
  },
  required: ['hypothesis','matched_pairs','total_pairs','success'],
};

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    claim_reproduced: { type: 'boolean' },
    independent_test: { type: 'string' },
    overfit_risk: { type: 'string' },
    verdict: { type: 'string', enum: ['CONFIRMED','REFUTED','INCONCLUSIVE'] },
  },
  required: ['claim_reproduced','verdict'],
};

phase('Recon')
const reconTasks = [
  { label:'recon:B-program', prompt:`${CTX}\n\nTASK: Resolve exactly what bytecode PROGRAM + constants F uses. Disassemble huongB_devirt19/bin/libmetasec_ov.so around 0x1384b0-0x1384e8 (the call site of F). Recover the adrp+add sequences that build x0, x2, x3 (they point to a program descriptor + constant tables) and x1/x4 (output buffers). Follow those pointers into the binary (.rodata/.data), dump the referenced bytes, and identify the bytecode program the VM runs for F. Also compare with the report-assembly call site at 0x9fd58-0x9fd70 and the index-gen at 0x10ac60-0x10ac80 to isolate what is UNIQUE to F. Report the program/table offsets + any embedded constants. Run capstone; do not guess.` },
  { label:'recon:dispatch', prompt:`${CTX}\n\nTASK: Document the VM dispatch mechanism. Disassemble around 0x55890 (the 'br' dispatch) and 0x52924 (entry). Determine: how the opcode is fetched from the bytecode stream, how operands are decoded (XOR 0x6a9091b9), where the handler jump table lives, and how x23(bytecode ptr)/x24(regfile)/predicate 0x9b374 are used. Produce a precise description enabling a Python re-implementation of the fetch-decode-dispatch loop.` },
  { label:'recon:ops-compute', prompt:`${CTX}\n\nTASK: Reverse the VM compute handlers op18, op38, op15 (the arithmetic/micro-op handlers; op38/op15 use 0x20-byte micro-op entries [fn_ptr,p1,p2,p3]). Find each handler via the dispatch table, disassemble, and give exact semantics (what registers/memory each reads/writes, the operation performed) with a Python sketch per opcode.` },
  { label:'recon:ops-ratchet', prompt:`${CTX}\n\nTASK: Reverse op40 (ratchet, handler 0x5b8fc: pointer XOR 0xa123f43, byte ^0xed self-modifying decrypt), op44 (computed control-flow), and op1 (state transition). Give exact semantics + Python sketch. Explain how the ratchet buffer (regfile[29]) evolves per request and how an index/counter could feed it.` },
  { label:'recon:fingerprint', prompt:`${CTX}\n\nTASK: Fingerprint the crypto primitive of F. Scan huongB_devirt19/bin/libmetasec_ov.so for known cipher signatures: AES sbox (63 7c 77 7b...), SM4 sbox, Simon/Speck round-constant/z-sequences, TEA/XTEA delta 0x9e3779b9, DES, and any 256-byte permutation tables. Report every table found with its offset. Then, near F's program/constants (call site 0x1384e4; see also 0x19b520 key), identify which primitive is most likely. Prioritize Simon/Speck (SDK uses Simon). Run code to scan; list concrete offsets.` },
];
const recon = await parallel(reconTasks.map(t => () =>
  agent(t.prompt, { label:t.label, phase:'Recon', schema:RECON_SCHEMA, effort:'high' })));

phase('Cryptanalysis')
const cryptTasks = [
  { label:'crypt:simon', prompt:`${CTX}\n\nTASK: Attack the 13 golden (seed->slot16) pairs (constant PSK) with the SIMON block cipher (TOP SUSPECT). Implement Simon (pure python) for block/key sizes: Simon64/128, Simon128/128, Simon128/256, Simon64/96, Simon48/96, Simon96/96. For each: key = PSK (32B) or PSK[:keylen] or PSK-derived; plaintext = seed expanded to blocksize (seed, seed*repeat, seed|zeros, seed|rticket) OR seed as an index/counter block. Try BOTH encrypt and decrypt, forward and byte-swapped I/O. A construction WINS only if it reproduces ALL 13 slot16. Report exact formula if found.` },
  { label:'crypt:speck-tea', prompt:`${CTX}\n\nTASK: Attack the 13 pairs with SPECK (all sizes) and the TEA/XTEA/XXTEA family (delta 0x9e3779b9). Same key/plaintext strategy as the Simon agent (PSK-derived key, seed as block or as counter/index; enc & dec; endianness variants). WIN = reproduce all 13. Report formula if found; else report ruled-out set.` },
  { label:'crypt:modaes-sm4', prompt:`${CTX}\n\nTASK: Attack the 13 pairs assuming a MODIFIED AES or SM4 (custom S-box / reduced rounds). First scan the binary for any 256-byte sbox/table and EXTRACT it. Implement AES and SM4 that accept a custom sbox; try reduced-round (1..10) AES and SM4 with the extracted sbox, key=PSK-derived, block=seed-expansion. Also try AES with standard sbox but modified round count / no final MixColumns. WIN = all 13. Report.` },
  { label:'crypt:arx-prng', prompt:`${CTX}\n\nTASK: Attack the 13 pairs two ways. (A) Generic ARX / the custom 80-round ARX hash referenced near 0xa0c38 in prior notes — implement plausible ARX permutations of (PSK, seed). (B) Treat seed as an INDEX into a PSK-keyed generator: build candidate keystreams/permutations from PSK using the embedded keys (.data@0x960, 0x19b520) via Simon/Speck/AES-CTR and check if slot16[i] equals block[index] where index derives from seed. WIN = all 13. Report structure even if partial.` },
  { label:'crypt:structure', prompt:`${CTX}\n\nTASK: Structural cryptanalysis of the 13 pairs (constant PSK, 4-byte seed -> 16-byte slot16). Determine: is the map seed->slot16 injective? Does flipping one seed bit avalanche ~half the output bits (full cipher) or less (reduced round)? Is any output byte/word a low-degree function of seed bytes (test linearity/affine over GF(2) per output bit using the 13 samples)? Is slot16 possibly a PERMUTATION/reordering of a fixed 16-byte-per-index keystream? Report the cipher shape these tests imply (block size, likely round count, key coupling) to constrain the other agents. Run real computations.` },
];
const crypt = await parallel(cryptTasks.map(t => () =>
  agent(t.prompt, { label:t.label, phase:'Cryptanalysis', schema:CRYPT_SCHEMA, effort:'high' })));

const anyMatch = crypt.filter(Boolean).find(c => c && c.matched);

phase('Synthesize')
const reconTxt = recon.filter(Boolean).map((r,i)=>`RECON[${reconTasks[i].label}] prim=${JSON.stringify(r.primitive_candidates)} conf=${r.confidence}\n  ${r.summary}\n  findings=${JSON.stringify(r.key_findings)}\n  constants=${JSON.stringify(r.constants_or_tables||[])}\n  sketch=${r.python_sketch||''}`).join('\n\n');
const cryptTxt = crypt.filter(Boolean).map((c,i)=>`CRYPT[${cryptTasks[i].label}] matched=${c.matched} formula=${c.match_formula||''}\n  partial=${c.partial_hits||''}\n  notes=${c.notes}`).join('\n\n');
const synth = await agent(
  `${CTX}\n\nYou are the SYNTHESIS step. Below are recon + cryptanalysis results from parallel agents.\n\n=== RECON ===\n${reconTxt}\n\n=== CRYPTANALYSIS ===\n${cryptTxt}\n\nTASK: Form the single best hypothesis for F, implement it in huongB_devirt19/compute_slot16.py as compute_slot16(psk_bytes, seed_bytes)->16 bytes, and TEST it against all 13 rows of huongB_devirt19/_corr_data.json. If a cryptanalysis agent already found a full match, implement that and confirm. If not, combine the strongest recon primitive-ID with the structural constraints to build and test the most likely candidate (iterate a few variants). Report matched_pairs/total_pairs and the exact formula. Write the file even if partial. Run the test yourself.`,
  { label:'synthesize', phase:'Synthesize', schema:SYNTH_SCHEMA, effort:'high' });

phase('Verify')
let verify = null;
if (synth && synth.success) {
  verify = await agent(
    `${CTX}\n\nA prior agent claims F is SOLVED: formula="${synth.formula}", file=huongB_devirt19/compute_slot16.py, matched ${synth.matched_pairs}/${synth.total_pairs}. ADVERSARIALLY VERIFY: re-implement the formula INDEPENDENTLY from scratch (do not import their file), run it against all 13 rows of _corr_data.json yourself, and check for overfitting (e.g. a formula with enough free params to fit 13 points spuriously — a real cipher match on 13x 16-byte outputs is ~unforgeable, but confirm the construction is a standard/plausible cipher not a lookup). Give verdict CONFIRMED only if your independent code reproduces all 13.`,
    { label:'verify', phase:'Verify', schema:VERIFY_SCHEMA, effort:'high' });
}

return { solved: !!(synth && synth.success), synth, verify, anyMatch: !!anyMatch,
         recon: recon.filter(Boolean).length, crypt: crypt.filter(Boolean).length };
