#!/usr/bin/env python3
"""DLL boundary audit: gResourceDescriptors (retail dol) vs splits.txt units.

Walks every gResourceDescriptors entry (dol 0x802C6300, size 0xB08; index =
DLL id), reads each ObjectDescriptor's fn pointers (+0x10..; slot count
bounded by the symbols.txt object size, else the delta to the next known
descriptor, else 10), maps every fn to its splits.txt .text unit, and flags
descriptors whose fn range is CUT by a unit boundary.

Object names / DLL ids come from the retail ISO: OBJECTS.bin + OBJECTS.tab
(name = NUL-terminated ASCII at def+0x91, fixed 11-char field; DLL id = >H at
def+0x50); OBJINDEX.bin gives romlist-type -> def reachability.

TU model (validated on dll_0215_wmnewcrystal.c): descriptor fns lie in
reverse slot order ascending (getExtraSize first, initialise last); a DLL's
TU spans (previous DLL's initialise end) .. (own initialise end) — helper
fns precede the descriptor fns they serve and belong to the FOLLOWING
descriptor's TU.

Usage:
  python3 tools/dll_boundary_audit.py            # summary + cut table
  python3 tools/dll_boundary_audit.py --census   # per-unit dll census
  python3 tools/dll_boundary_audit.py --map LO HI [--syms]  # window map
  python3 tools/dll_boundary_audit.py --md       # markdown for docs/
"""
import struct, bisect, re, sys, os
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOL = os.path.join(REPO, "orig/GSAE01/sys/main.dol")
ISO = os.path.join(REPO, "orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso")

RESDESC_ADDR, RESDESC_SIZE = 0x802C6300, 0xB08
OBJECTS_BIN_OFF, OBJECTS_BIN_SZ = 0xB390E90, 301696
OBJECTS_TAB_OFF, OBJECTS_TAB_N = 0xB424490, 1480
OBJINDEX_OFF, OBJINDEX_N = 0xB42ECD0, 2192


def load():
    dol = open(DOL, "rb").read()
    offs = struct.unpack(">18I", dol[0x0:0x48])
    addrs = struct.unpack(">18I", dol[0x48:0x90])
    sizes = struct.unpack(">18I", dol[0x90:0xD8])
    sections = [(addrs[i], addrs[i] + sizes[i], offs[i]) for i in range(18) if sizes[i] > 0]

    def rd32(va):
        for a0, a1, o in sections:
            if a0 <= va < a1:
                return struct.unpack(">I", dol[o + (va - a0):o + (va - a0) + 4])[0]
        return None

    text_lo = 0x80004000
    text_hi = max(a1 for a0, a1, o in sections if a0 < 0x802C0000)

    units = []
    cur = None
    for line in open(os.path.join(REPO, "config/GSAE01/splits.txt")):
        s = line.rstrip("\n")
        if s and s[0] not in " \t" and s.endswith(":"):
            cur = s[:-1]
        elif cur and "start:" in s:
            m = re.search(r"^\s*(\S+)\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)", s)
            if m and m.group(1) == ".text":
                units.append((int(m.group(2), 16), int(m.group(3), 16), cur))
    units.sort()
    ustarts = [u[0] for u in units]

    def unit_for(a):
        i = bisect.bisect_right(ustarts, a) - 1
        if i >= 0 and units[i][0] <= a < units[i][1]:
            return units[i][2]
        return None

    fn_addrs, fn_size, sym_at, sym_size = [], {}, {}, {}
    for line in open(os.path.join(REPO, "config/GSAE01/symbols.txt")):
        m = re.match(r"^(\S+) = (\.\w+):(0x[0-9A-Fa-f]+);(.*)$", line)
        if not m:
            continue
        a = int(m.group(3), 16)
        sym_at[a] = m.group(1)
        ms = re.search(r"size:(0x[0-9A-Fa-f]+)", m.group(4))
        if ms:
            sym_size[a] = int(ms.group(1), 16)
        if m.group(2) == ".text":
            fn_addrs.append(a)
            fn_size[a] = int(ms.group(1), 16) if ms else 0
    fn_addrs.sort()

    def fn_end(a):
        sz = fn_size.get(a, 0)
        if sz:
            return a + sz
        i = bisect.bisect_right(fn_addrs, a)
        return fn_addrs[i] if i < len(fn_addrs) else a + 4

    iso = open(ISO, "rb")
    iso.seek(OBJECTS_TAB_OFF)
    tab = struct.unpack(">%dI" % OBJECTS_TAB_N, iso.read(OBJECTS_TAB_N * 4))
    iso.seek(OBJECTS_BIN_OFF)
    objbin = iso.read(OBJECTS_BIN_SZ)
    iso.seek(OBJINDEX_OFF)
    objindex = struct.unpack(">%dh" % OBJINDEX_N, iso.read(OBJINDEX_N * 2))

    dll_names, dll_reach = defaultdict(list), defaultdict(bool)
    reachable = set(v for v in objindex if v >= 0)
    for di in range(OBJECTS_TAB_N):
        off = tab[di]
        nxt = tab[di + 1] if di + 1 < OBJECTS_TAB_N else OBJECTS_BIN_SZ
        if off >= OBJECTS_BIN_SZ or nxt > OBJECTS_BIN_SZ or nxt <= off:
            continue
        did = struct.unpack(">H", objbin[off + 0x50:off + 0x52])[0]
        b = objbin[off + 0x91:min(nxt, off + 0x91 + 24)]
        e = b.find(b"\0")
        nm = b[:e].decode("ascii", "replace") if e > 1 else "?"
        dll_names[did].append(nm)
        if di in reachable:
            dll_reach[did] = True

    desc_of = {}
    for did in range(RESDESC_SIZE // 4):
        p = rd32(RESDESC_ADDR + did * 4)
        if p:
            desc_of[did] = p
    desc_addrs = sorted(set(desc_of.values()))

    def nslots(dp):
        sz = sym_size.get(dp)
        if sz and sz >= 0x14:
            return min(14, (sz - 0x10) // 4)
        i = bisect.bisect_right(desc_addrs, dp)
        if i < len(desc_addrs):
            return min(14, max(0, (desc_addrs[i] - dp - 0x10) // 4))
        return 10

    rows = []
    for did, dp in sorted(desc_of.items()):
        fns = []
        for slot in range(nslots(dp)):
            v = rd32(dp + 0x10 + slot * 4)
            if v and text_lo <= v < text_hi and v % 4 == 0:
                fns.append((slot, v))
        lo = min((v for _, v in fns), default=None)
        hi = max((v for _, v in fns), default=None)
        fn_units = sorted(set(unit_for(v) or "(unclaimed)" for _, v in fns))
        rows.append(dict(dll_id=did, desc=dp, desc_sym=sym_at.get(dp), fns=fns,
                         lo=lo, hi=hi, fn_units=fn_units,
                         names=dll_names.get(did, []), reach=dll_reach.get(did, False)))
    return rows, units, unit_for, fn_end, sym_at, fn_size


def cut_rows(rows, units, unit_for, fn_end):
    his = sorted((r["hi"], r) for r in rows if r["hi"])

    def tu_start(r):
        prev = None
        for h, rr in his:
            if h < r["lo"]:
                prev = h
            else:
                break
        return fn_end(prev) if prev else None

    out = []
    for r in sorted((r for r in rows if r["lo"]), key=lambda r: r["lo"]):
        if len(r["fn_units"]) <= 1:
            continue
        inner = [(st, unit_for(st - 4), u) for st, en, u in units if r["lo"] < st <= r["hi"]]
        out.append((r, inner, tu_start(r), fn_end(r["hi"])))
    return out


def main():
    rows, units, unit_for, fn_end, sym_at, fn_size = load()
    if "--map" in sys.argv:
        i = sys.argv.index("--map")
        lo, hi = int(sys.argv[i + 1], 16), int(sys.argv[i + 2], 16)
        events = []
        for st, en, u in units:
            if lo <= st <= hi:
                events.append((st, 0, "UNIT-START %s" % u))
        for r in rows:
            if r["lo"] and lo <= r["lo"] <= hi:
                events.append((r["lo"], 2, "dll 0x%03X LO  %s names=%s reach=%s" % (
                    r["dll_id"], r["desc_sym"], ",".join(r["names"][:3]), r["reach"])))
            if r["hi"] and lo <= r["hi"] <= hi:
                events.append((r["hi"], 3, "dll 0x%03X HI+sz=%08X %s" % (
                    r["dll_id"], fn_end(r["hi"]), r["desc_sym"])))
        if "--syms" in sys.argv:
            for a in sorted(set(a for a in sym_at if lo <= a <= hi and a in fn_size)):
                events.append((a, 4, "  fn %s (0x%X)" % (sym_at[a], fn_size.get(a, 0))))
        for a, k, txt in sorted(events):
            print("%08X  %s" % (a, txt))
        return
    cuts = cut_rows(rows, units, unit_for, fn_end)
    if "--census" in sys.argv:
        unit_dlls = defaultdict(set)
        for r in rows:
            for s, v in r["fns"]:
                u = unit_for(v)
                if u:
                    unit_dlls[u].add(r["dll_id"])
        for u in sorted(unit_dlls):
            ids = sorted(unit_dlls[u])
            if len(ids) < 2 and "--all" not in sys.argv:
                continue
            names = []
            for did in ids:
                rr = next(x for x in rows if x["dll_id"] == did)
                names.append("0x%03X:%s" % (did, rr["names"][0] if rr["names"] else (rr["desc_sym"] or "?")))
            print("%-55s %d dlls: %s" % (u, len(ids), ", ".join(names)))
        return
    md = "--md" in sys.argv
    nfns = [r for r in rows if r["fns"]]
    nodef = [r for r in rows if not r["names"]]
    print("descriptors (non-null ptr): %d   with text fns: %d" % (len(rows), len(nfns)))
    print("cut by a unit boundary: %d    no OBJECTS.bin def: %d" % (len(cuts), len(nodef)))
    print()
    if md:
        print("| dll | descriptor | fn range | TU (proposed) | cutting boundary(ies) | reach | names |")
        print("|---|---|---|---|---|---|---|")
    for r, inner, ts, te in cuts:
        bs = "; ".join("%08X (%s \\| %s)" % (st, l, rgt) if md else "%08X (%s | %s)" % (st, l, rgt)
                       for st, l, rgt in inner)
        if md:
            print("| 0x%03X | %s | %08X-%08X | %s-%08X | %s | %s | %s |" % (
                r["dll_id"], r["desc_sym"] or "?", r["lo"], r["hi"],
                ("%08X" % ts) if ts else "?", te, bs, "Y" if r["reach"] else "n",
                ",".join(r["names"][:4])))
        else:
            print("dll 0x%03X %-34s [%08X-%08X] TU=[%s-%08X] reach=%s names=%s" % (
                r["dll_id"], r["desc_sym"] or "?", r["lo"], r["hi"],
                ("%08X" % ts) if ts else "?", te, r["reach"], ",".join(r["names"][:4])))
            for st, l, rgt in inner:
                print("    boundary %08X  %s | %s" % (st, l, rgt))


if __name__ == "__main__":
    main()
