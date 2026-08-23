#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_lifter.py — Python VM lifter for the metasec custom VM at 0x55950.
#
# Architecture (from static analysis):
#   - VM is a single-step interpreter: each call to 0x55950 processes ONE opcode
#   - Dispatch (0x55890): opcode_idx = opcode_word & 0x3f -> handler table -> br x15
#   - XOR key for operand decryption: 0x6a9091b9 (from 0x55978-0x5597c)
#   - Register file: x24 points to 32x8-byte slots
#   - Bytecode: x23 points to current 8-byte entry (opcode_word + operand)
#   - Handlers jump to exit path (0xedb2c) which:
#     a) Zeros regfile[0..N-1]
#     b) Copies data from bytecode to regfile using mapping table at R[25]
#     c) Calls callback at [x22] with (R[22], R[20], R[19])
#   - Bytecode is MIXED opcode+data: each opcode entry is followed by data slots
#
# Handler entry state (from dispatch at 0x5590c-0x55930):
#   w8  = R[21] (lower 32 bits) — used as argument by handlers
#   w9  = R[20] (lower 32 bits)
#   w10 = R[26] (lower 32 bits)
#   w11 = R[27] (lower 32 bits)
#   w12 = (R[27] >> 0x1b) & 0x1f = reg_b
#   w13 = R[19] & 0x1f = reg_a
#   w14 = R[28] (lower 32 bits)
#   x0  = preserved from caller (points to micro-opcode context for opcodes 38/15)
#   x1  = preserved from caller (points to register file for micro-opcodes)
#
# Micro-opcode system (opcodes 38/15 — state machine):
#   Each micro-op entry is 0x20 bytes:
#     +0x00: function pointer (8B) — loaded by previous entry's ldr x4, [x0, #0x20]!
#     +0x08: param A (varies: float64, int32, pointer, or reg index)
#     +0x10: param B (varies)
#     +0x18: param C (typically dstReg as int32)
#   Chain: ldr x4, [x0, #0x20]! (pre-increment x0 by 0x20, load next fn ptr)
#   Terminal: table lookup → new x0 context → ret (return to caller)
#   Op38 terminal: 3D table at 0x1df390: table[row*32 + col*16 + sub*8]
#   Op15 terminal: 2D table at 0x1df6d0: table[row*16 + col*8]
#   Op38 has 11 micro-op types (float/double/int compare, store bool result)
#   Op15 has 11 micro-op types (sign-extend, zero reg, load u16 from table/reg)
#
# PLT function map (verified from .rela.plt):
#   0x30610 = sigaddset     0x30760 = std::thread::join
#   0x30770 = strtod        0x30b40 = readdir
#   0x309d0 = getppid       0x30c10 = unlink
#   0x30620 = getpid        0x30c20 = puts
#   0x305a0 = sigemptyset   0x30940 = fork
#
# Run: python _vm_lifter.py
import os, sys, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SO = "bin/libmetasec_ov.so"
LOAD_BASE = 0x6f5fe00000
XOR_KEY = 0x6a9091b9

# ── Captured VM state (from _vm_entry_capture.js, call #1) ──
BYTECODE_HEX = (
    "6c953f00ac08aa24ac082a0de6024a83920002002a8060e92a804eec2a406eed2a0062e92c043300"
    "6c953f000f175087ac086a8cac08020da6426483920002002a804ced2a4042e92c1409002c240b00"
    "2c0433006c953f000f175887ac08020d920604ab2a4084e8920002002a804ced2a4042e92c140900"
    "2c240b002c0433006c953f00ac08ea0c2a4042e892060288ac086a082a0042e892060287ac086a08"
    "2ac022e89206028bac086a082a8022e89206028cac086a082a4022e89206028dac086a082a0002e8"
    "9206028eac086a082a8062e8920602ab2a0082e80f17408bac08020d2a4062e8260142832a0062e8"
    "26416e83664242832ac042e80f17488b"
)

REGFILE_HEX = (
    "00000000000000000000006f5fe766280000006f608e06480000006f276e90800000006f5fe76e68"
    "0000006f276e91680000006f5ffda1a00000006f5fe76e5c0000006f5fe7a6b800000000000000c5"
    "0000006f276e9c8000000071f6cf18b0000000000000001a0000006f276e927000000073116ce540"
    "000000000000001a0000006f5fe76e5c0000006f608e06680000006f608e06580000006f608e0718"
    "0000006f60a59b20ffffffffff59682000000070e6c592b80000006f276e934800000073116d8abc"
    "0000006f5fe76e5c00000073116d89400000006f276e932000000073116d43000000006f276e8ff0"
    "ffffffffff5900000000006f5ff7c938"
)

# Parse register file
regfile = []
for i in range(32):
    val = int(REGFILE_HEX[i*16:(i+1)*16], 16)
    regfile.append(val)

# Parse bytecode
bytecode = bytes.fromhex(BYTECODE_HEX)

# ── PLT function names (verified from .rela.plt) ──
PLT_NAMES = {
    0x30610: "sigaddset",
    0x30620: "getpid",
    0x30760: "std::thread::join",
    0x30770: "strtod",
    0x30b40: "readdir",
    0x309d0: "getppid",
    0x30c10: "unlink",
    0x30c20: "puts",
    0x305a0: "sigemptyset",
    0x30940: "fork",
    0x30b50: "__cxa_finalize",
    0x309e0: "__cxa_atexit",
    0x30600: "malloc",
    0x30580: "free",
    0x303c0: "memcpy",
    0x30680: "memmove",
    0x30920: "memset",
    0x306c0: "strlen",
    0x305f0: "strcmp",
    0x307c0: "strncmp",
    0x30490: "rename",
    0x30860: "remove",
    0x30480: "kill",
    0x30a50: "sigaction",
    0x308a0: "sigprocmask",
    0x308b0: "pthread_create",
    0x306f0: "pthread_self",
    0x30700: "gettid",
    0x306a0: "pthread_once",
    0x30b30: "std::this_thread::sleep_for",
    0x30b20: "std::chrono::system_clock::now",
    0x303e0: "gettimeofday",
    0x30550: "clock_gettime",
    0x30be0: "time",
    0x30b60: "localtime",
    0x30bf0: "uname",
    0x30c40: "sysinfo",
    0x30950: "stat",
    0x30510: "lstat",
    0x30880: "fstatat",
    0x306e0: "access",
    0x30690: "faccessat",
    0x303d0: "fopen",
    0x30740: "fclose",
    0x30590: "fread",
    0x30850: "ftell",
    0x30a10: "fseek",
    0x30430: "opendir",
    0x305e0: "mkdir",
    0x30cb0: "utime",
    0x30a40: "ptrace",
    0x309a0: "ioctl",
    0x30bd0: "socket",
    0x30a00: "setsockopt",
    0x307a0: "munmap",
    0x30b00: "mprotect",
    0x30890: "madvise",
    0x30b90: "npth_dlsym",
    0x307e0: "npth_dlopen",
    0x307b0: "dladdr",
    0x30c60: "__cxa_demangle",
    0x30530: "__android_log_write",
    0x30840: "__android_log_print",
    0x30c00: "__stack_chk_fail",
    0x309c0: "abort",
    0x30a20: "exit",
    0x30ca0: "std::terminate",
    0x307f0: "__cxa_pure_virtual",
}

# ── Handler table at 0x1d9488 (RW segment) ──
def load_handler_table():
    with open(SO, "rb") as f:
        so = f.read()
    # vaddr 0x1d9488 -> file offset 0x1d5488 (second segment: vaddr=0x1d8f88, offset=0x1d4f88)
    HT_FILE_OFF = 0x1d5488
    handlers = []
    for i in range(64):
        val = struct.unpack_from("<Q", so, HT_FILE_OFF + i * 8)[0]
        handlers.append(val)
    return handlers

HANDLER_TABLE = load_handler_table()

# ── Opcode decoding ──
def decode_opcode(opcode_word):
    """Decode an opcode word into its fields."""
    idx = opcode_word & 0x3f
    return {
        'idx': idx,
        'handler_vaddr': HANDLER_TABLE[idx] if idx < 64 else 0,
        'raw': opcode_word,
    }

def xor_decrypt_operand(encrypted_operand):
    """XOR-decrypt the operand with the VM's key."""
    return (encrypted_operand & 0xFFFFFFFF) ^ XOR_KEY

def plt_name(addr):
    """Get the function name for a PLT address."""
    return PLT_NAMES.get(addr, f"plt_0x{addr:x}")

# ── VM State ──
class VMState:
    def __init__(self, regfile_vals, bytecode_data):
        self.R = list(regfile_vals)
        self.bytecode = bytearray(bytecode_data)
        self.pc = 0
        self.trace = []

    def next_opcode(self):
        if self.pc >= len(self.bytecode):
            return None
        off = self.pc
        opcode_word = struct.unpack_from("<I", self.bytecode, off)[0]
        operand = struct.unpack_from("<I", self.bytecode, off + 4)[0]
        self.pc += 8
        info = decode_opcode(opcode_word)
        info['operand_enc'] = operand
        info['operand_dec'] = xor_decrypt_operand(operand)
        info['offset'] = off
        return info

    def dispatch_fields(self):
        """Extract the dispatch fields from the register file (matching 0x5590c-0x5592c)."""
        return {
            'R19': self.R[19],
            'R20': self.R[20],
            'R21': self.R[21],
            'R26': self.R[26],
            'R27': self.R[27],
            'R28': self.R[28],
            'reg_a': self.R[19] & 0x1f,            # and w11, w19, #0x1f
            'reg_b': (self.R[27] >> 0x1b) & 0x1f,  # lsr w12, w27, #0x1b
            # Additional fields from 0x559f4-0x55a0c
            'R27_12_16': (self.R[27] >> 12) & 0x1f,  # ubfx w14, w11, #0xc, #5
            'R27_17_21': (self.R[27] >> 17) & 0x1f,  # ubfx w13, w11, #0x11, #5
            'R27_22_26': (self.R[27] >> 22) & 0x1f,  # ubfx w12, w11, #0x16, #5
        }

    def __repr__(self):
        return f"VMState(pc={self.pc}, R[16]=0x{self.R[16]:016x})"


# ── VM Interpreter ──
class VMInterpreter:
    def __init__(self, state):
        self.state = state

    def step(self):
        op = self.state.next_opcode()
        if op is None:
            return False

        idx = op['idx']
        handler_vaddr = op['handler_vaddr']
        fields = self.state.dispatch_fields()

        print(f"  [{op['offset']//8:2d}] opcode={idx:2d} handler=0x{handler_vaddr:x} "
              f"opword=0x{op['raw']:08x} "
              f"operand_enc=0x{op['operand_enc']:08x} "
              f"operand_dec=0x{op['operand_dec']:08x}")
        print(f"       R21=0x{fields['R21']:016x} R20=0x{fields['R20']:016x} "
              f"R26=0x{fields['R26']:016x} R28=0x{fields['R28']:016x}")
        print(f"       reg_a=R{fields['reg_a']} reg_b=R{fields['reg_b']} "
              f"R27_fields=[{fields['R27_12_16']},{fields['R27_17_21']},{fields['R27_22_26']}]")

        handler_name = f"opcode_{idx:02d}"
        handler = getattr(self, handler_name, None)
        if handler:
            handler(op, fields)
        else:
            print(f"    [UNIMPLEMENTED] opcode {idx} at 0x{handler_vaddr:x}")

        return True

    def run(self, max_steps=32):
        for _ in range(max_steps):
            if not self.step():
                break

    # ── Opcode handlers ──

    def opcode_44(self, op, f):
        """Opcode 44 — handler at 0xedec0. Calls sigaddset + bytecode pointer advance.
        Full disassembly:
          0xedec0: mov x0, x8           ; x0 = w8 = R[21] (sigset_t* arg)
          0xedec4: mov x23, x8          ; x23 = w8 (temp, x23 restored later)
          0xedec8: bl #0x30610          ; call sigaddset(sigset_t*, int)
          0xedecc: cbz x0, #0xedfb4     ; if ret==0, error/retry path
          0xeded0: ldr w8, [sp, #0x10]  ; w8 = saved x5 (from VM entry)
          0xeded4: str x0, [x28]        ; *R[28] = sigaddset retval
          0xeded8: ldr x10, [sp, #0x18] ; x10 = saved x6
          0xededc: str w8, [x28, #0xc]  ; *(R[28]+12) = w8
          0xedee0: ldr x8, [x20, #0x10] ; x8 = *(R[20]+0x10) — bytecode stride table
          0xedee4: str w24, [x28, #8]   ; *(R[28]+8) = w24 (R[24] lower 32 bits)
          0xedee8: ldr x9, [x8]         ; x9 = table.base
          0xedeec: ldr w8, [x8, #8]     ; w8 = table.stride
          0xedef0: add x8, x9, x8, lsl#3 ; x8 = base + stride*8
          0xedef4: lsl x9, x10, #3      ; x9 = x10 * 8
          0xedef8: sub x1, x8, x9       ; x1 = x8 - x9 (regfile base for next op)
          0xedefc: sub x23, x1, x9      ; x23 = x1 - x9 (new bytecode pointer)
          0xedf00: b #0xedb2c           ; -> exit path
        Error path (0xedfb4): retries sigaddset with readdir(0x30b40) between attempts.
          After 5 retries, calls puts(0x30c20)+abort (0x309d0).
        Semantics: R[21] holds a sigset_t pointer (allocated by previous opcode).
          Calls sigaddset to add a signal to the set. Stores result to *R[28].
          Computes new bytecode pointer from stride table at *(R[20]+0x10).
          The stride table is: {base: u64, stride: u32} — new x23 = base - (2 * x10 * 8).
        """
        dec = op['operand_dec']
        r21_lo = f['R21'] & 0xFFFFFFFF
        print(f"    [44] sigaddset(x0=0x{r21_lo:08x}) -> *R[28]=0x{f['R28']:x}")
        print(f"         R[21]=0x{f['R21']:016x} (sigset_t*), R[20]=0x{f['R20']:016x} (stride table)")

    def opcode_42(self, op, f):
        """Opcode 42 — handler at 0xf7470. Table-driven memory lookup.
        Full disassembly (entry):
          0xf7470: b.hi #0xf7e6c        ; opaque predicate branch (always taken or not)
          0xf7474: ldr w10, [x8, #0xc]  ; w10 = *(w8+12) — R[21] is a pointer!
          0xf7478: ldr w9, [x5]         ; w9 = *R[5] (key value)
          0xf747c: mov w10, w10
          0xf7480: str x10, [x26, #0x10]; *(R[26]+0x10) = w10
          0xf7484: ldr w10, [x8, #0x14] ; w10 = *(w8+20)
          0xf7488: cmp w9, w10          ; if key > *(w8+20)
          0xf748c: b.ls #0xf8318        ;   -> bounds check fail
          0xf7490: ldr w8, [x8, #0x1c]  ; w8 = *(w8+28)
          0xf7494: cmp w9, w8           ; if key > *(w8+28)
          0xf7498: b.ls #0xf8318        ;   -> bounds check fail
          0xf749c: ldr x9, [x6]         ; x9 = *R[6] (table base)
          0xf74a0: ldr w11, [x1, #0x88] ; w11 = *(R[1]+0x88) (index)
          0xf74a4-0xf74c0: compute table indices
          0xf74c4: ldr x11, [x12, x11]  ; load from table
          0xf74c8-0xf74d8: compute offsets, load entries
          0xf74e8: stp x9, x8, [x26, #0x18] ; store pair to R[26]+0x18
          0xf74ec: mov x26, x10         ; x26 = result pointer
          0xf74f0: b #0xf799c           ; -> continue to sub-path
        Sub-path 0xf799c:
          0xf79a0: add x23, x23, #1     ; increment use counter
          0xf79a4: str w8, [x3]         ; store result flag
          0xf79e8-0xf7a44: chain lookup through linked list
        Semantics: R[21] is a POINTER to a struct with fields at +0xc, +0x14, +0x1c.
          R[5] holds the lookup key. R[6] is a table base.
          Performs a bounds-checked table lookup and stores results to R[26] area.
          This is a hash-table or sorted-map lookup operation.
        """
        dec = op['operand_dec']
        print(f"    [42] table-lookup: key=*R[5]=0x{self.state.R[5]:x} R[6]=0x{self.state.R[6]:x}")
        print(f"         R[21]=0x{f['R21']:016x} (struct ptr) -> fields [+0xc,+0x14,+0x1c]")

    def opcode_18(self, op, f):
        """Opcode 18 — handler at 0xf60a0. Calls strtod (string-to-double).
        Full disassembly:
          0xf60a0: mov x1, x24          ; x1 = x24 (R[24] — string pointer)
          0xf60a4: bl #0x30760          ; call strtod(R[24], NULL)
          0xf60a8: cbnz x0, #0xf5f94    ; if ret!=0, success path
          0xf60ac-0xf60ec: error path — retries strtod with readdir(0x30b40),
            then tries with x23 as arg. After 5 retries, gives up.
        Success path (0xf5f94):
          0xf5f94: ldr x8, [x27, #0x18] ; thread-local storage
          0xf5f98: add x9, x0, #0x400   ; x9 = x0 + 0x400 (result buffer)
          0xf5f9c: adrp x23, #0x1f6000  ; x23 = global data page
          0xf5fa0: stp x0, x9, [x27]    ; save to TLS
          0xf5fa4: add x8, x9, x8       ; x8 = x9 + tls[0x18]
          0xf5fa8: str x8, [x27, #0x10] ; save to TLS
          0xf5fac: ldr w8, [x23, #0xf78] ; check global flag
          0xf5fb0: cbnz w8, #0xf6054    ; if flag set, skip
          0xf5fb4-0xf5fd8: calls sub-function at [x21+0x18]
        Semantics: Converts string at R[24] to double via strtod. On success,
          stores result in thread-local storage and calls sub-function.
          R[24] contains a pointer to a string to parse.
          The strtod result (double) is stored in x0 and written to TLS.
        """
        dec = op['operand_dec']
        print(f"    [18] strtod(x1=R[24]=0x{self.state.R[24]:x})")
        print(f"         R[19]=0x{self.state.R[19]:x} R[20]=0x{self.state.R[20]:x}")

    def opcode_38(self, op, f):
        """Opcode 38 — handler at 0xf3dc8. Micro-opcode chain (float/double/int compare).
        Entry format: 0x20 bytes per micro-op
          +0x00: next function pointer (8 bytes, loaded by previous entry)
          +0x08: param A (varies: float64, int32, or reg index)
          +0x10: param B (varies)
          +0x18: param C (typically dest reg index as int32)

        Micro-op catalog (10 distinct types):
          [0] 0xf3dc8: Entry — fcmp s1, s0; store bool to [x1+x8] (s0,s1,x8 from dispatch)
          [1] 0xf3ddc: Float reg-reg — fcmp regfile[A], regfile[B]; store to dstReg
          [2] 0xf3e14: Double imm-imm — fcmp imm0, imm1; store to dstReg
          [3] 0xf3e38: Double imm-reg — fcmp imm, regfile[B]; store to dstReg
          [4] 0xf3e64: Double reg-imm — fcmp regfile[A], imm; store to dstReg
          [5] 0xf3e90: Double reg-reg — fcmp regfile[A], regfile[B]; store to dstReg
          [6] 0xf3ec0: TERMINAL — 3D table lookup at 0x1df390 → new x0; ret
          [7] 0xf3ee8: Int imm-imm — cmp immA, immB; cset le; store to dstReg
          [8] 0xf3f10: Int imm-reg — cmp imm, regfile[B]; cset le; store to dstReg
          [9] 0xf3f40: Int reg-imm — cmp regfile[A], imm; cset le; store to dstReg
          [10]0xf3f70: Int reg-reg — cmp regfile[A], regfile[B]; cset le; store to dstReg

        Terminal table (0x1df390): 3D indexed by dispatch_ptr fields:
          row = *(dispatch_ptr+0x12) as u16, col = *(dispatch_ptr+8) as u8,
          sub = *(dispatch_ptr+0x10) as u8
          entry = 0x1df390 + row*32 + col*16 + sub*8

        Chain mechanism: ldr x4, [x0, #0x20]! pre-increments x0 by 0x20
        and loads the next entry's function pointer. This is a state machine
        where each opcode 38 invocation processes one micro-op and transitions.
        """
        dec = op['operand_dec']
        print(f"    [38] micro-op chain: float/double/int compare -> state machine transition")
        print(f"         x0 (micro-op ctx) and x1 (regfile ptr) from caller context")

    def opcode_15(self, op, f):
        """Opcode 15 — handler at 0xf4a88. Micro-opcode chain (sign-extend/load/store).
        Entry format: 0x20 bytes per micro-op (same as opcode 38)

        Micro-op catalog (10 distinct types):
          [0] 0xf4a88: Entry — sign-extend w8; store to regfile[x9] (x8,x9 from dispatch)
          [1] 0xf4aa0: Zero reg — regfile[dstReg] = 0
          [2] 0xf4ab0: Zero reg — regfile[dstReg] = 0 (dup entry)
          [3] 0xf4ac0: Zero reg — regfile[dstReg] = 0 (dup entry)
          [4] 0xf4ad0: Zero reg — regfile[dstReg] = 0 (dup entry)
          [5] 0xf4ae0: TERMINAL — 2D table lookup at 0x1df6d0 → new x0; ret
          [6] 0xf4b00: Load u16 from table — regfile[dst] = *(base + offset) as u16
          [7] 0xf4b18: Load u16 from reg+off — regfile[dst] = *(regfile[reg] + off) as u16
          [8] 0xf4b38: Load u16 from table — regfile[dst] = *(base + offset) as u16
          [9] 0xf4b50: Load u16 from reg+off — regfile[dst] = *(regfile[reg] + off) as u16
          [10]0xf4b70: Zero reg — regfile[dstReg] = 0

        Terminal table (0x1df6d0): 2D indexed by dispatch_ptr fields:
          row = *(dispatch_ptr+2) as u16, col = *(dispatch_ptr+8) as u8
          entry = 0x1df6d0 + row*16 + col*8

        State machine architecture: opcode 38 and 15 together form a two-phase
        computation engine. Op38 compares values and stores booleans; op15
        loads data and stores sign-extended values. Both use table-driven
        terminal micro-ops to transition states.
        """
        dec = op['operand_dec']
        print(f"    [15] micro-op chain: sign-extend/load/store -> state machine transition")
        print(f"         x0 (micro-op ctx) and x1 (regfile ptr) from caller context")


# ── Main ──
def main():
    print("=== VM Lifter — Bytecode Analysis with XOR Decrypt ===\n")
    print(f"XOR key: 0x{XOR_KEY:08x}")
    print(f"Bytecode: {len(bytecode)} bytes ({len(bytecode)//8} opcodes)\n")

    # Print full bytecode analysis
    print("Bytecode (with XOR-decrypted operands):")
    for i in range(0, len(bytecode), 8):
        opcode_word = struct.unpack_from("<I", bytecode, i)[0]
        operand = struct.unpack_from("<I", bytecode, i + 4)[0]
        info = decode_opcode(opcode_word)
        dec = xor_decrypt_operand(operand)
        dec_idx = dec & 0x3f
        print(f"  [{i//8:2d}] opword=0x{opcode_word:08x} idx={info['idx']:2d} "
              f"enc=0x{operand:08x} dec=0x{dec:08x} dec_idx={dec_idx:2d}")

    # Print register file
    print("\nRegister file (initial):")
    for i in range(32):
        v = regfile[i]
        kind = ""
        if 0x6f5fe00000 <= v < 0x6f5fff0000:
            kind = " (.so + 0x{:x})".format(v - 0x6f5fe00000)
        elif 0x6f20000000 <= v < 0x7000000000:
            kind = " (stack)"
        elif 0x7000000000 <= v < 0x8000000000:
            kind = " (heap)"
        elif v == 0:
            kind = " (zero)"
        elif v & 0xffff000000000000 == 0xffff000000000000:
            kind = " (sign-extended)"
        print(f"  R[{i:2d}] = 0x{v:016x}{kind}")

    # Print handler table
    print("\nHandler table (non-default entries):")
    for i in range(64):
        if HANDLER_TABLE[i] != 0xf87d8:
            print(f"  [{i:2d}] -> 0x{HANDLER_TABLE[i]:x}")

    # Opcode frequency analysis
    from collections import Counter
    opcode_counts = Counter()
    for i in range(0, len(bytecode), 8):
        opcode_word = struct.unpack_from("<I", bytecode, i)[0]
        opcode_counts[opcode_word & 0x3f] += 1
    print("\nOpcode frequency in this bytecode:")
    for idx, count in opcode_counts.most_common():
        print(f"  opcode {idx:2d}: {count}x")

    # Run the VM
    print("\n=== VM Execution Trace ===")
    state = VMState(regfile, bytecode)
    vm = VMInterpreter(state)
    vm.run(max_steps=32)

    print(f"\nFinal state: {state}")
    print(f"\nKey findings:")
    print(f"  - Only 5 distinct opcodes used: {sorted(opcode_counts.keys())}")
    print(f"  - Opcodes 38/15 are micro-opcode chains (sub-VM within VM)")
    print(f"  - Opcode 44 calls sigaddset with R[21] as sigset_t* pointer")
    print(f"  - Opcode 18 calls strtod (string-to-double conversion)")
    print(f"  - Opcode 42 does table-driven memory lookups (hash table)")
    print(f"  - Exit path (0xedb2c) copies data from bytecode to regfile via mapping table")
    print(f"  - Bytecode is mixed opcode+data: each opcode entry has data slots")
    print(f"  - R[21] is a struct pointer, NOT a scratch register")
    print(f"  - R[25] (x25) points to control structure with mapping table at +0x60")
    print(f"  - R[28] is output buffer (heap) for handler results")
    print(f"")
    print(f"  === LIVE CAPTURE (2026-08-23, phone SM-G930S) ===")
    print(f"  - VM ran 122,944 times for ONE login -> confirmed single-step interpreter")
    print(f"  - Bytecode header per block: 6c953f00 (op 44). Words LE, op_idx = word & 0x3f")
    print(f"  - Embedded strings in bytecode: '%s/%s%s' + '.msp_' (metasec state file path)")
    print(f"  - Control struct (x25) STATIC FORMULA (fn 0xeda2c @ 0xedadc):")
    print(f"      x25 = idx*0x130 + base")
    print(f"        base = *(x8+0x58).lo   where x8 = *R[20] = *(x2)")
    print(f"        idx  = table[R[22]]    (bounds: R[22] <= *(x8+0x88))")
    print(f"      each control-struct entry = 0x130 bytes")
    print(f"  - callback x22 = *(*(x8+0x108) + idx*0x18)  [0xedaf4]")
    print(f"  - output buf x28 = *(R[20]+0x10)  [0xedb0c]")
    print(f"  - x26 = *(R[21]+0x20)  [0xedb14]")
    print(f"  - Full simulation needs: exit-path capture (trigger fresh auth request)")


if __name__ == "__main__":
    main()