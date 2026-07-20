#!/usr/bin/env python3
import json, os, re, subprocess, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VER = "GSAE01"
BUILD = os.path.join(ROOT, "build", VER)
OBJDUMP = os.path.join(ROOT, "build", "binutils", "powerpc-eabi-objdump")

LOADS = ("lbz", "lhz", "lwz", "lfs", "lfd", "lha")
NARROW = ("clrlwi", "extsb", "extsh", "rlwinm")


def ninja_objects():
    out = set()
    p = os.path.join(BUILD, "build.ninja")
    if not os.path.exists(p):
        p = os.path.join(ROOT, "build.ninja")
    txt = open(p, errors="ignore").read()
    for m in re.finditer(r"[^\s:]*build/%s/src/[^\s:]+\.o" % VER, txt):
        out.add(os.path.basename(m.group(0)))
        out.add(m.group(0))
    return txt


def disasm(path):
    r = subprocess.run([OBJDUMP, "-M", "gekko", "-d", path],
                       capture_output=True, text=True)
    funcs = collections.defaultdict(list)
    cur = None
    for line in r.stdout.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"^\s+[0-9a-f]+:\t(?:[0-9a-f]{2} ){4}\t(\S+)", line)
        if m and cur:
            funcs[cur].append(m.group(1))
    return funcs


def main():
    report = json.load(open(os.path.join(BUILD, "report.json")))
    ninja = ninja_objects()
    rows = []
    for unit in report["units"]:
        name = unit["name"]
        rel = name.split("main/", 1)[-1] if name.startswith("main/main/") else name
        srcobj = os.path.join(BUILD, "src", "main", rel.split("main/", 1)[-1] + ".o")
        tgtobj = os.path.join(BUILD, "obj", "main", rel.split("main/", 1)[-1] + ".o")
        if not (os.path.exists(srcobj) and os.path.exists(tgtobj)):
            continue
        if os.path.basename(srcobj) not in ninja and srcobj.replace(ROOT + "/", "") not in ninja:
            continue
        fns = {f["name"]: f for f in (unit.get("functions") or [])
               if f.get("fuzzy_match_percent", 100) < 100}
        if not fns:
            continue
        try:
            cur = disasm(srcobj)
            tgt = disasm(tgtobj)
        except Exception:
            continue
        for fname, f in fns.items():
            if fname not in cur or fname not in tgt:
                continue
            c = collections.Counter(cur[fname])
            t = collections.Counter(tgt[fname])
            load_def = sum(max(0, t[m] - c[m]) for m in LOADS)
            narrow_sur = sum(max(0, c[m] - t[m]) for m in NARROW)
            if load_def == 0 and narrow_sur == 0:
                continue
            size = f.get("size", 0)
            try:
                size = int(size)
            except Exception:
                size = 0
            wb = size * (100.0 - f["fuzzy_match_percent"]) / 100.0
            rows.append((wb, load_def, narrow_sur, name, fname,
                         f["fuzzy_match_percent"], size,
                         len(cur[fname]) - len(tgt[fname])))
    rows.sort(reverse=True)
    print("%-8s %5s %5s %6s %5s  %s" % ("wB", "ldΔ", "nrwΔ", "fuzzy", "insΔ", "unit :: fn"))
    for wb, ld, nr, unit, fn, fz, size, insd in rows[:60]:
        print("%8.1f %5d %5d %6.2f %5d  %s :: %s" % (wb, ld, nr, fz, insd, unit, fn))
    print("\ntotal hits: %d" % len(rows))


main()
