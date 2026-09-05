import importlib.util
spec = importlib.util.spec_from_file_location("it", "_inner_test.py")
it = importlib.util.module_from_spec(spec); spec.loader.exec_module(it)
pts,_=it.parse_pts()

# known HITs (from earlier) for reference: idx0 L560, idx1 L544, idx11 L576
# MISS band = idx 82..99 (L 592/608)
def show(idx):
    iev,L,pt=pts[idx]
    head=pt[:4].hex()          # [0xEC][nonce...]
    tail=pt[-16:].hex()        # last 16B (tail region 15B + boundary)
    rb23=pt[-15:-13].hex()
    region=pt[9:-15]           # what gets simon-decoded
    return iev,L,head,rb23,tail,len(region),len(region)%16

print("idx  ev   L    head(4)   rb23  reglen reg%16  tail(last16)")
print("--- HIT band (5..81 sample) ---")
for idx in (0,1,11,40,60,81):
    iev,L,head,rb23,tail,rl,rm=show(idx)
    print(f"{idx:<4} {iev:<4} {L:<4} {head}  {rb23}  {rl:<5} {rm:<6} {tail}")
print("--- MISS band (82..99) ---")
for idx in range(82,100):
    if idx>=len(pts): break
    iev,L,head,rb23,tail,rl,rm=show(idx)
    print(f"{idx:<4} {iev:<4} {L:<4} {head}  {rb23}  {rl:<5} {rm:<6} {tail}")

# Do all pt share the same nonce[1:4]? and same const tail suffix?
print("\n--- tail suffix const check (last 3 bytes) ---")
from collections import Counter
c_hit=Counter(pts[i][2][-3:].hex() for i in range(5,82))
c_miss=Counter(pts[i][2][-3:].hex() for i in range(82,min(100,len(pts))))
print("HIT  last3:", c_hit.most_common(4))
print("MISS last3:", c_miss.most_common(4))
print("\n--- nonce byte pt[0:4] pattern ---")
print("HIT  head4:", Counter(pts[i][2][:4].hex() for i in range(5,82)).most_common(5))
print("MISS head4:", Counter(pts[i][2][:4].hex() for i in range(82,min(100,len(pts)))).most_common(5))
