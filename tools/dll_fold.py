"""Move area-prefixed DLL .c files into their lane folders (CF/, DIM/, ...),
updating configure.py + config/GSAE01/splits.txt. Lane assignment is the
ROM-object-name prefix mapping learned from docs/dll_naming_manifest.md.

Moving a source file is byte-neutral (.o content is independent of the source
path -- verified): every moved unit's new-path .o must md5-match its old-path
.o, else the whole operation aborts and is reverted. Lanes with < MIN_LANE
files stay in root.

Usage: python3 tools/dll_fold.py [--min N] [--apply]
"""
import json
import os
import re
import subprocess
import sys
import hashlib
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(REPO)
MIN_LANE = 4
if '--min' in sys.argv:
    MIN_LANE = int(sys.argv[sys.argv.index('--min') + 1])

fold = json.load(open('/tmp/sfa_clean/fold_map.json'))
counts = Counter(fold.values())
fold = {u: l for u, l in fold.items()
        if counts[l] >= MIN_LANE and os.path.exists('src/' + u)}
print(f"{len(fold)} units -> {len(set(fold.values()))} lanes (min {MIN_LANE})")


def obj_md5(path):
    return hashlib.md5(open(path, 'rb').read()).hexdigest() if os.path.exists(path) else None


def old_obj(u):
    return 'build/GSAE01/src/' + u[:-2] + '.o'


def new_obj(u, lane):
    return f'build/GSAE01/src/main/dll/{lane}/{os.path.basename(u)[:-2]}.o'


if '--apply' not in sys.argv:
    for u, l in sorted(fold.items()):
        print(f"  {u} -> main/dll/{l}/{os.path.basename(u)}")
    raise SystemExit(0)

# 1. baseline .o md5 per unit
base = {}
for u in fold:
    m = obj_md5(old_obj(u))
    if m is None:
        raise SystemExit(f"baseline .o missing for {u} -- run a full build first")
    base[u] = m

# 2. edit configure.py + splits.txt with per-unit verification, git mv files
cfg = open('configure.py').read()
spl = open('config/GSAE01/splits.txt').read()
for u, lane in fold.items():
    name = os.path.basename(u)
    newu = f'main/dll/{lane}/{name}'
    assert f'"{u}"' in cfg, f"configure.py has no \"{u}\""
    assert re.search(r'(?m)^' + re.escape(u) + r':', spl), f"splits.txt has no {u}:"
    cfg = cfg.replace(f'"{u}"', f'"{newu}"')
    spl = re.sub(r'(?m)^' + re.escape(u) + r':', newu + ':', spl)
    os.makedirs(f'src/main/dll/{lane}', exist_ok=True)
    subprocess.run(['git', 'mv', f'src/{u}', f'src/{newu}'], check=True)
open('configure.py', 'w').write(cfg)
open('config/GSAE01/splits.txt', 'w').write(spl)

# 3. clean regen + build
for f in ('build/GSAE01/config.json', 'objdiff.json'):
    if os.path.exists(f):
        os.remove(f)
subprocess.run(['python3', 'configure.py'], check=True)
# NonMatching src .o are not built by the default target -- build them explicitly
new_objs = [new_obj(u, lane) for u, lane in fold.items()]
r = subprocess.run(['ninja'] + new_objs, capture_output=True)
if b'FAILED' in r.stdout + r.stderr:
    print((r.stdout + r.stderr).decode()[-2000:])
    raise SystemExit("BUILD FAILED -- inspect; revert with git")

# 4. verify every moved unit's .o content unchanged
bad = []
for u, lane in fold.items():
    m = obj_md5(new_obj(u, lane))
    if m != base[u]:
        bad.append((u, base[u], m))
if bad:
    for u, b, m in bad[:20]:
        print(f"MISMATCH {u}: {b} -> {m}")
    raise SystemExit(f"{len(bad)} units changed bytes -- REVERT with git")
print(f"\n✓ all {len(fold)} moved units byte-identical -- zero regression")
