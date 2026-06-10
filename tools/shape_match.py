#!/usr/bin/env python3
"""Prologue-skeleton shape matcher against the MP4 matched corpus (#108 oracle).

For a given SFA fn, extract its TARGET prologue web signature (the ordered
list of (op-kind, dest-reg) for the first N saved-reg defining instructions)
and rank MP4 matched fns by skeleton similarity. The top hits' C (greppable
in reference_projects/marioparty4/src) shows the decl/structure pattern that
produces that coloring — the transplant source.

Usage: python3 tools/shape_match.py <unit> <fn> [--top N]
Requires /tmp/mp4_asm_cache.txt (built by tools/mp4_asm_search.py).
"""
import subprocess, re, sys

unit, fn = sys.argv[1], sys.argv[2]
top = 8
def skeleton(body, n=10):
    """ordered (kind, reg) for saved-reg-defining instrs in the first ~40 lines"""
    sig = []
    for m in re.finditer(r'\t(mr|lwz|li|addi|lis|lbz|lhz|lha)\s+(r(?:2[4-9]|3[01])),', body):
        sig.append((m.group(1), m.group(2)))
        if len(sig) >= n: break
    return sig

out = subprocess.run(['python3','tools/function_objdump.py',unit,fn],capture_output=True,text=True,timeout=120).stdout
tbody = out.split('===== current')[0]
tsig = skeleton(tbody)
print('SFA target skeleton:', tsig)

cache = open('/tmp/mp4_asm_cache.txt', errors='ignore').read()
blocks = re.split(r'(?m)^[0-9a-f]{8} <(\w+)>:$', cache)
scored = []
for i in range(1, len(blocks)-1, 2):
    name, body = blocks[i], blocks[i+1]
    s = skeleton(body[:2500])
    if not s: continue
    # similarity: longest common prefix of (kind,reg) + same-kind sequence bonus
    lcp = 0
    for a, b in zip(tsig, s):
        if a == b: lcp += 2
        elif a[0] == b[0]: lcp += 1
        else: break
    if lcp >= 3:
        scored.append((lcp, name, s[:6]))
scored.sort(reverse=True)
for sc, name, s in scored[:top]:
    print(f'{sc:3d} {name}: {s}')
