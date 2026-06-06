#!/usr/bin/env python3
"""Extern width vs symbols.txt data:N annotation mismatch enumerator (task #176).

Flags scalar extern declarations whose C type width contradicts symbols.txt's
data annotation, ranked by the consuming functions' fuzzy% (mismatches inside
<100% fns are live fix candidates).

Findings from the first sweep (keep in mind when triaging):
- A mismatch in a fn at 100% means the EXTERN is right and the symbols.txt
  annotation is drift — do NOT retype symbols.txt (recipe #70: score-neutral
  at best, extern-orphaning risk at worst).
- u8/char ARRAY externs on 4byte/float data are the deliberate byte-blob
  overlay pattern (access width comes from cast-derefs at use sites, not the
  element type) — excluded by default, --arrays to include.
- Scalar u8 externs used only via &sym are the sda21 address-of form
  (see "Passing a .sdata string BY ADDRESS") — deliberate, skip.
- The real wins are WRONG-SYMBOL imports (TrickyCurve read half of double
  lbl_803E70D0 where target uses f32 lbl_803E6438 -> fn to 100%) and
  s16/s8-vs-4byte counters (lha/extsh/sth vs target lwz/stw).

Usage: python3 tools/width_audit.py [--all] [--arrays]
  default: only mismatches whose consuming fn is <100%
  --all:   print every mismatch
"""
import re, json, sys, subprocess
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
ALL = '--all' in sys.argv
ARRAYS = '--arrays' in sys.argv

widths = {}
for l in open(repo / 'config/GSAE01/symbols.txt'):
    m = re.match(r'(\w+) = [^;]+;.*data:(\S+)', l)
    if not m:
        continue
    name, d = m.groups()
    if d == 'byte':
        w = 1
    elif d == '2byte':
        w = 2
    elif d in ('4byte', 'float') or d.startswith('0x80'):
        w = 4
    elif d == 'double':
        w = 8
    else:
        continue  # string/unknown
    widths[name] = (w, d)

tw = {'s8': 1, 'u8': 1, 'char': 1, 'undefined1': 1,
      's16': 2, 'u16': 2, 'short': 2, 'undefined2': 2,
      's32': 4, 'u32': 4, 'int': 4, 'uint': 4, 'long': 4,
      'f32': 4, 'float': 4, 'undefined4': 4,
      'f64': 8, 'double': 8}

pat = r'^\s*extern\s+(const\s+)?\w+\s+\**\w+\s*(\[[^]]*\])?\s*;'
out = subprocess.run(['grep', '-rn', '-E', pat, str(repo / 'src')],
                     capture_output=True, text=True).stdout

report = repo / 'build/GSAE01/report.json'
unitfns = {}
if report.exists():
    r = json.load(open(report))
    for u in r['units']:
        unitfns[u['name']] = {f['name']: f.get('fuzzy_match_percent')
                              for f in u.get('functions', [])}

def unit_for(f):
    p = f.replace(str(repo) + '/', '').replace('src/', 'main/').replace('.c', '')
    for un in unitfns:
        if un.endswith(p):
            return un

n = 0
for l in out.splitlines():
    m = re.match(r'([^:]+):(\d+):\s*extern\s+(?:const\s+)?(\w+)\s+(\**)(\w+)\s*(\[[^]]*\])?\s*;', l)
    if not m:
        continue
    f, ln, typ, ptr, name, arr = m.groups()
    if name not in widths or (typ not in tw and not ptr):
        continue
    cw = 4 if ptr else tw.get(typ)
    if cw is None:
        continue
    sw, kind = widths[name]
    if arr and not ARRAYS:
        continue
    if ptr and kind.startswith('0x80'):
        continue
    if cw == sw:
        continue
    un = unit_for(f)
    live = []
    if un:
        src = open(f).read().splitlines()
        uses = [i for i, sl in enumerate(src) if name in sl and 'extern' not in sl]
        fns = set()
        for ui in uses:
            for j in range(ui, -1, -1):
                fm = re.match(r'^(?:static\s+)?\w[\w *]*?(\w+)\s*\(', src[j])
                if fm and '=' not in src[j] and ';' not in src[j]:
                    fns.add(fm.group(1))
                    break
        for fn in fns:
            p = unitfns[un].get(fn)
            if p is not None and p < 100:
                live.append((fn, round(p, 2)))
    if live or ALL:
        print(f'{f}:{ln}: {typ}{ptr}{arr or ""} {name} ({cw}B) vs data:{kind} ({sw}B)'
              + (f'  LIVE: {live}' if live else ''))
        n += 1
print(f'-- {n} mismatches shown', file=sys.stderr)
