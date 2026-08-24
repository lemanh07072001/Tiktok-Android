// P1: Full bytecode execution trace hook
// Capture EVERY opcode dispatch + regfile mutation
// Output: execution_trace.json

const MODULE = "libmetasec_ov.so";
const SM3_ADDR = 0xa0748;  // SM3 compress (signal: #19 hash start)
const DISPATCH_ADDR = 0x55890;  // br x15 (opcode dispatch)

let base = 0;
let trace = [];
let capture_active = false;
let dispatch_count = 0;

function readReg(name) {
    const reg_map = {
        'x0': 0, 'x1': 1, 'x2': 2, 'x3': 3, 'x4': 4, 'x5': 5, 'x6': 6, 'x7': 7,
        'x8': 8, 'x9': 9, 'x10': 10, 'x11': 11, 'x12': 12, 'x13': 13, 'x14': 14, 'x15': 15,
        'x16': 16, 'x17': 17, 'x18': 18, 'x19': 19, 'x20': 20, 'x21': 21, 'x22': 22, 'x23': 23,
        'x24': 24, 'x25': 25, 'x26': 26, 'x27': 27, 'x28': 28, 'x29': 29, 'x30': 30,
    };
    let idx = reg_map[name];
    if (idx === undefined) return null;
    return ptr(this.context[name.replace('x', 'x')]);
}

function dumpRegfile(x24_ptr, label) {
    try {
        if (!x24_ptr || x24_ptr.isNull()) return null;
        let buf = x24_ptr.readByteArray(256);  // 32 qwords
        return buf;
    } catch (e) {
        console.log(`[!] Regfile read failed (${label}): ${e}`);
        return null;
    }
}

function onSM3Entry(context) {
    // Signal start of #19 computation (regfile[29] likely reset or initialized)
    capture_active = true;
    dispatch_count = 0;
    trace = [];
    console.log(`[*] SM3 entry @ 0x${context.pc} — starting trace`);
}

function onDispatch(context) {
    if (!capture_active || dispatch_count > 5000) return;

    try {
        // Read bytecode pointer (x23) and regfile (x24)
        let x23 = context.x23;
        let x24 = context.x24;

        // Read bytecode word at [x23] = opcode
        let bc_word = x23.add(0).readU64();
        let op = bc_word & 0x3f;
        let operands = bc_word >> 6;

        // Read regfile[29] (ratchet)
        let regfile = dumpRegfile(x24, `dispatch#${dispatch_count}`);

        trace.push({
            dispatch: dispatch_count,
            op: op,
            operands: operands.toString(16),
            bytecode_ptr: x23.toString(),
            regfile: regfile ? regfile : null,  // Will be hex string in output
        });

        dispatch_count++;
        if (dispatch_count % 100 === 0) {
            console.log(`  [D#${dispatch_count}] op${op}`);
        }
    } catch (e) {
        console.log(`  [!] Dispatch hook error: ${e}`);
    }
}

function onExit() {
    // Trace complete, save to file
    console.log(`[*] Trace complete: ${dispatch_count} dispatches`);

    // Convert regfile buffers to hex strings
    trace.forEach(t => {
        if (t.regfile) {
            t.regfile = t.regfile.toString('hex');
        }
    });

    let output = {
        meta: {
            dispatches: dispatch_count,
            timestamp: Date.now(),
        },
        trace: trace,
    };

    // Save to /data/local/tmp/execution_trace.json
    let file_path = "/data/local/tmp/execution_trace.json";
    let file = new File(file_path, "w");
    file.write(JSON.stringify(output, null, 2));
    file.close();

    console.log(`[+] Trace saved to ${file_path}`);
    console.log(`[+] Ready: adb pull ${file_path} ./`);
}

function main() {
    let mod = Process.getModuleByName(MODULE);
    if (!mod) {
        console.log(`[!] ${MODULE} not found`);
        return;
    }
    base = mod.base;
    console.log(`[+] ${MODULE} base: 0x${base}`);

    // Hook SM3 (signal start)
    Interceptor.attach(base.add(SM3_ADDR), {
        onEnter(args) {
            onSM3Entry(this.context);
        }
    });

    // Hook dispatch (br x15 at 0x55890)
    Interceptor.attach(base.add(DISPATCH_ADDR), {
        onEnter(args) {
            onDispatch(this.context);
        }
    });

    // Hook exit (regfile output read)
    let exit_addr = base.add(0x55968);  // Hypothetical exit point
    Interceptor.attach(exit_addr, {
        onEnter(args) {
            onExit();
        }
    });

    console.log("[+] Hooks installed. Let app run to trigger #19 computation.");
    console.log("[*] Waiting for SM3 entry...");
}

setImmediate(main);
