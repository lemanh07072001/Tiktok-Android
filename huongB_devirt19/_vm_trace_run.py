#!/usr/bin/env python3
"""_vm_trace_run.py — Run VM record-stream tracer on AVD or phone.

Usage:
  python _vm_trace_run.py [spawn|attach] [duration_secs] [out_json]

Examples:
  python _vm_trace_run.py spawn 120 _vm_trace_out.json
  python _vm_trace_run.py attach 60 _vm_trace_out.json
"""
import frida, sys, time, json, os

IDENT = "com.zhiliaoapp.musically"
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vm_trace.js")
DEVICE_ADDR = "127.0.0.1:47119"


def run_spawn(dur, outjson):
    dev = frida.get_device_manager().add_remote_device(DEVICE_ADDR)
    pid = dev.spawn([IDENT])
    session = dev.attach(pid)
    sc = session.create_script(open(SCRIPT).read())
    msgs = []
    t0 = time.time()

    def on(m, d):
        if m.get("type") != "send":
            print("[msg]", str(m)[:220], flush=True)
            return
        p = m["payload"]
        msgs.append(p)
        t = int(time.time() - t0)
        tag = p.get("t", "?")
        if tag == "VM_TRACE_DUMP":
            print(f"[{t}s] ★ VM_TRACE_DUMP traceLen={p.get('traceLen',0)} nVm={p.get('nVm',0)}", flush=True)
            trig = p.get("trigger", {})
            print(f"[{t}s]   slot16={trig.get('slot16','?')} P={trig.get('P','?')}", flush=True)
        elif tag == "TRIGGER":
            info = p.get("info", {})
            print(f"[{t}s] TRIGGER seq={info.get('seq')} slot16={info.get('slot16')}", flush=True)
        elif tag == "mon":
            print(f"[{t}s] mon nVm={p.get('nVm',0)} nDrv={p.get('nDrv',0)} dumped={p.get('dumped',False)}", flush=True)
        else:
            print(f"[{t}s] {json.dumps(p)[:300]}", flush=True)
        if outjson:
            json.dump(msgs, open(outjson, "w"), indent=1)

    sc.on("message", on)
    sc.load()
    dev.resume(pid)
    print(f"[*] SPAWNED pid={pid} script=_vm_trace.js {dur}s", flush=True)

    while time.time() - t0 < dur:
        time.sleep(1)
    if outjson:
        json.dump(msgs, open(outjson, "w"), indent=1)
    print(f"[DONE] msgs={len(msgs)}", flush=True)


def run_attach(dur, outjson):
    dev = frida.get_device_manager().add_remote_device(DEVICE_ADDR)
    # Find the app process
    for proc in dev.enumerate_processes():
        if proc.name == IDENT or IDENT in proc.name:
            pid = proc.pid
            break
    else:
        print(f"[!] Process {IDENT} not found", flush=True)
        return
    session = dev.attach(pid)
    sc = session.create_script(open(SCRIPT).read())
    msgs = []
    t0 = time.time()

    def on(m, d):
        if m.get("type") != "send":
            print("[msg]", str(m)[:220], flush=True)
            return
        p = m["payload"]
        msgs.append(p)
        t = int(time.time() - t0)
        tag = p.get("t", "?")
        if tag == "VM_TRACE_DUMP":
            print(f"[{t}s] ★ VM_TRACE_DUMP traceLen={p.get('traceLen',0)} nVm={p.get('nVm',0)}", flush=True)
            trig = p.get("trigger", {})
            print(f"[{t}s]   slot16={trig.get('slot16','?')} P={trig.get('P','?')}", flush=True)
        elif tag == "TRIGGER":
            info = p.get("info", {})
            print(f"[{t}s] TRIGGER seq={info.get('seq')} slot16={info.get('slot16')}", flush=True)
        elif tag == "mon":
            print(f"[{t}s] mon nVm={p.get('nVm',0)} nDrv={p.get('nDrv',0)} dumped={p.get('dumped',False)}", flush=True)
        else:
            print(f"[{t}s] {json.dumps(p)[:300]}", flush=True)
        if outjson:
            json.dump(msgs, open(outjson, "w"), indent=1)

    sc.on("message", on)
    sc.load()
    print(f"[*] ATTACHED pid={pid} script=_vm_trace.js {dur}s", flush=True)

    while time.time() - t0 < dur:
        time.sleep(1)
    if outjson:
        json.dump(msgs, open(outjson, "w"), indent=1)
    print(f"[DONE] msgs={len(msgs)}", flush=True)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "spawn"
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    outjson = sys.argv[3] if len(sys.argv) > 3 else None

    if mode == "spawn":
        run_spawn(dur, outjson)
    elif mode == "attach":
        run_attach(dur, outjson)
    else:
        print(f"Usage: {sys.argv[0]} [spawn|attach] [duration_secs] [out_json]")
        sys.exit(1)