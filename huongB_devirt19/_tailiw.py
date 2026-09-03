import json
LINES=open('_vm_trace11.out.jsonl').read().splitlines()
E=[json.loads(l) for l in LINES[1:] if l.strip()]; E.sort(key=lambda e:e['seq'])
by={e['seq']:e for e in E}
print("=== tail raw iw/niw + rf snapshot (base-reg candidates) ===")
for s in range(612,621):
    e=by[s]
    iw=e['iw']; niw=e['niw']
    print(f"seq{s} op{e['op']:2d} bc0x{e['bc']:x} iw=0x{iw:08x} niw=0x{niw:08x}")
# For op18 @seq619 print the full rf so we can resolve base reg values
e=by[619]
print("\nseq619 rf (before op18 that loads r22<-77e4e63fa0):")
for i,v in enumerate(e['rf']): print(f"  r{i:2d}=0x{int(v,16):x}")
