#!/usr/bin/env python3
"""lwz-histogram re-derive detector (the #55/#107 faithful-form finder).

For each <100% fn (or a given unit/fn), compare the offset histograms of
lwz displacement loads between target and current .o. When TARGET loads the
same offset MORE times than current, the original source RE-DERIVES a
pointer chain that our import caches in a named local -- the faithful fix
is recipe #107 un-naming (inline the chain per use) or a #55 block-local
re-read. Found cnthitobjec hitDetect (+1.0) and waterflowwe
calcCurrentVector (+1.4) in its first run.

Usage: python3 tools/rederive_scan.py [unit-substr] [--min-pct N] [--limit N]
"""
import subprocess, json, re, sys
from collections import Counter

args = [a for a in sys.argv[1:] if not a.startswith('--')]
flt = args[0] if args else None
minpct = 90.0
limit = 200
skip = 0
for a in sys.argv[1:]:
    if a.startswith('--min-pct'): minpct = float(a.split('=')[1])
    if a.startswith('--limit'): limit = int(a.split('=')[1])
    if a.startswith('--skip'): skip = int(a.split('=')[1])

r = json.load(open('build/GSAE01/report.json'))
todo = []
for u in r['units']:
    um = u['measures']
    if int(um.get('total_code',0))>0 and minpct <= float(um.get('fuzzy_match_percent',0)) < 100:
        un = u['name'].replace('\\','/').replace('main/','',1)
        if flt and flt not in un: continue
        for f in u.get('functions',[]):
            p = float(f.get('fuzzy_match_percent',0))
            if p < 100 and p >= 95 and int(f.get('size',0)) >= 200:
                todo.append((un, f['name'], p))

print(f'{len(todo)} fns; scanning up to {limit}', file=sys.stderr)
for un, fn, p in todo[skip:skip+limit]:
    try:
        out = subprocess.run(['python3','tools/function_objdump.py',un,fn],
                             capture_output=True,text=True,timeout=60).stdout
    except Exception:
        continue
    parts = out.split('===== current')
    if len(parts) < 2: continue
    def hist(s): return Counter(re.findall(r'lwz     r\d+,(\d+)\(r\d+\)', s))
    ht, hc = hist(parts[0]), hist(parts[1])
    extra = {k: (ht[k], hc.get(k,0)) for k in ht if ht[k] > hc.get(k,0) and ht[k] >= 2}
    if extra:
        print(f'{p:6.2f} {un} {fn}: ' + ', '.join(f'off{k} T={a} C={b}' for k,(a,b) in sorted(extra.items())[:4]))
