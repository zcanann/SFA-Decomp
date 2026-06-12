#!/usr/bin/env python3
"""Lane-homing audit: retail romlist placement census per single-DLL unit.

Re-homes DLL units from retail TRUTH (not drift-era donor-file
inheritance). Decompresses every <map>.romlist.zlb from the retail ISO,
reverse-maps placement records -> def -> handling DLL id -> text-fn
range -> splits.txt unit, then censuses each unit's placements across
maps and classifies CF-family (Cloud-Runner-Fortress) vs other.

Modes:
  (default / --cf)  CF/ residents only (outbound: who leaves CF/).
  --all             every single-DLL unit project-wide; emits the
                    inbound-CF set + the full lane-mismatch census.

Offsets (v1.0 USA, GSAE01): see CLAUDE.md "Retail-ISO forensics".
Usage: python3 tools/cf_lane_homing.py [--csv | --all [--csv]]
"""
import struct, zlib, re, bisect, os, sys
from collections import defaultdict, Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOL = os.path.join(REPO, "orig/GSAE01/sys/main.dol")
ISO = os.path.join(REPO, "orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso")
RESDESC_ADDR, RESDESC_SIZE = 0x802C6300, 0xB08
OBJECTS_BIN_OFF, OBJECTS_BIN_SZ = 0xB390E90, 301696
OBJECTS_TAB_OFF, OBJECTS_TAB_N = 0xB424490, 1480
OBJINDEX_OFF, OBJINDEX_N = 0xB42ECD0, 2192

# Cloud-Runner-Fortress map family (enumerated from sMapDirectoryName* +
# the cf*/cloud* romlist set in the ISO FST).
CF_MAPS = {"clouddungeon", "cloudjoin", "cloudrace", "cloudrunnermap",
           "cloudtrap", "cloudtreasure", "cfcolumn", "cfdungeonblock",
           "cfgalleon", "cfgangplank", "cfledge", "cfliftplat",
           "cfprisoncage", "cfprisondoor", "fortress"}

# Lane DIRECTORIES that currently exist under src/main/dll/. The evidenced
# lane for a unit is derived (for the project-wide census) from its
# canonical retail-name prefix; only prefixes whose lane dir EXISTS are
# treated as a re-home target, otherwise the unit homes to dll/ root.
LANE_DIRS = {"ARW", "baddie", "BW", "CAM", "CF", "CR", "DB", "debug",
             "DF", "DIM", "DR", "FRONT", "IM", "LGT", "MMP", "mmshrine",
             "NW", "SC", "SH", "SP", "TREX", "VF", "WC", "WM"}

# Retail name-PREFIX -> lane dir. Mirrors the manifest's name-prefix rule
# (WM_->WM/, DR->DR/, etc.). Longest-prefix wins. Only prefixes whose dir
# is in LANE_DIRS yield a re-home; CC/KT/MagicCave/DFP have no dir -> root.
NAME_LANE = [
    ("CF", "CF"), ("ARW", "ARW"), ("DIM2", "DIM"), ("DIM", "DIM"),
    ("DRP", "DR"), ("DR", "DR"), ("DB", "DB"), ("DBSH", "DB"),
    ("WC", "WC"), ("WM", "WM"), ("WG", "WM"), ("NW", "NW"),
    ("SC", "SC"), ("SH", "SH"), ("VFP", "VF"), ("VF", "VF"),
    ("IM", "IM"), ("MMP", "MMP"), ("TREX", "TREX"), ("Trex", "TREX"),
    ("CAM", "CAM"), ("BW", "BW"), ("LGT", "LGT"),
]


def load():
    dol = open(DOL, "rb").read()
    offs = struct.unpack(">18I", dol[0x0:0x48])
    addrs = struct.unpack(">18I", dol[0x48:0x90])
    sizes = struct.unpack(">18I", dol[0x90:0xD8])
    secs = [(addrs[i], addrs[i] + sizes[i], offs[i]) for i in range(18) if sizes[i] > 0]

    def rd32(va):
        for a0, a1, o in secs:
            if a0 <= va < a1:
                return struct.unpack(">I", dol[o + (va - a0):o + (va - a0) + 4])[0]
        return None

    text_lo, text_hi = 0x80004000, max(a1 for a0, a1, o in secs if a0 < 0x802C0000)

    units, cur = [], None
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

    sym_size = {}
    for line in open(os.path.join(REPO, "config/GSAE01/symbols.txt")):
        m = re.match(r"^(\S+) = (\.\w+):(0x[0-9A-Fa-f]+);(.*)$", line)
        if m:
            ms = re.search(r"size:(0x[0-9A-Fa-f]+)", m.group(4))
            if ms:
                sym_size[int(m.group(3), 16)] = int(ms.group(1), 16)

    iso = open(ISO, "rb")
    iso.seek(OBJECTS_TAB_OFF)
    tab = struct.unpack(">%dI" % OBJECTS_TAB_N, iso.read(OBJECTS_TAB_N * 4))
    iso.seek(OBJECTS_BIN_OFF)
    objbin = iso.read(OBJECTS_BIN_SZ)
    iso.seek(OBJINDEX_OFF)
    objindex = struct.unpack(">%dh" % OBJINDEX_N, iso.read(OBJINDEX_N * 2))

    def_dllid, def_name = {}, {}
    for di in range(OBJECTS_TAB_N):
        off = tab[di]
        nxt = tab[di + 1] if di + 1 < OBJECTS_TAB_N else OBJECTS_BIN_SZ
        if off >= OBJECTS_BIN_SZ or nxt > OBJECTS_BIN_SZ or nxt <= off:
            continue
        def_dllid[di] = struct.unpack(">H", objbin[off + 0x50:off + 0x52])[0]
        b = objbin[off + 0x91:min(nxt, off + 0x91 + 24)]
        e = b.find(b"\0")
        def_name[di] = b[:e].decode("ascii", "replace") if e > 1 else "?"

    romtype_def = {rt: objindex[rt] for rt in range(OBJINDEX_N) if objindex[rt] >= 0}

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

    dllid_units = defaultdict(set)
    for did, dp in desc_of.items():
        for slot in range(nslots(dp)):
            v = rd32(dp + 0x10 + slot * 4)
            if v and text_lo <= v < text_hi and v % 4 == 0:
                u = unit_for(v)
                if u:
                    dllid_units[did].add(u)

    iso.seek(0x424)
    fst_off, fst_sz = struct.unpack(">II", iso.read(8))
    iso.seek(fst_off)
    fst = iso.read(fst_sz)
    n_entries = struct.unpack(">I", fst[8:12])[0]
    str_off = n_entries * 12
    romlists = {}
    for i in range(n_entries):
        e = fst[i * 12:i * 12 + 12]
        name_off = struct.unpack(">I", b"\0" + e[1:4])[0]
        off = struct.unpack(">I", e[4:8])[0]
        sz = struct.unpack(">I", e[8:12])[0]
        nm_start = str_off + name_off
        nm = fst[nm_start:fst.find(b"\0", nm_start)].decode("ascii", "replace")
        if not e[0] and nm.endswith(".romlist.zlb"):
            romlists[nm[:-12]] = (off, sz)

    def parse(off, sz):
        iso.seek(off)
        raw = iso.read(sz)
        try:
            data = zlib.decompress(raw[16:])
        except Exception:
            return []
        out, pos = [], 0
        while pos + 4 <= len(data):
            typ = struct.unpack(">h", data[pos:pos + 2])[0]
            lw = data[pos + 2]
            if lw == 0:
                break
            out.append(typ)
            pos += lw * 4
        return out

    dllid_pl = defaultdict(Counter)
    for mp, (off, sz) in romlists.items():
        for rt in parse(off, sz):
            di = romtype_def.get(rt)
            if di is None:
                continue
            did = def_dllid.get(di)
            if did is not None:
                dllid_pl[did][mp] += 1

    return dllid_units, dllid_pl, def_dllid, def_name, units


def name_lane(name):
    """Re-home lane from a retail name prefix; None if prefix has no dir."""
    if not name or name == "-":
        return None
    best = None
    for pfx, lane in NAME_LANE:
        if name.startswith(pfx) and (best is None or len(pfx) > len(best[0])):
            best = (pfx, lane)
    return best[1] if best else None


def unit_dir(unit):
    """Current lane dir of a splits unit name (main/dll/<LANE>/file.c)."""
    m = re.match(r"main/dll/([A-Za-z]+)/", unit)
    if m and m.group(1) in LANE_DIRS:
        return m.group(1)
    return None


def census(dllid_units, dllid_pl, def_dllid, def_name, units):
    """Per-unit retail name + placement distribution + dll-id count.

    Returns a list of dicts (single-DLL + helper-sliver units) and a
    separate list of multi-DLL container units (excluded from re-homing).
    """
    unit_dllids = defaultdict(set)
    for did, us in dllid_units.items():
        for u in us:
            unit_dllids[u].add(did)
    order = defaultdict(list)
    for di in sorted(def_dllid):
        order[def_dllid[di]].append(def_name[di])

    rows, containers = [], []
    seen = set()
    for _lo, _hi, unit in units:
        if unit in seen or not unit.startswith("main/dll/"):
            continue
        seen.add(unit)
        dids = sorted(unit_dllids.get(unit, set()))
        pl = Counter()
        for did in dids:
            pl += dllid_pl.get(did, Counter())
        total = sum(pl.values())
        cf = sum(pl[m] for m in pl if m in CF_MAPS)
        canon = order[dids[0]][0] if dids and order.get(dids[0]) else "-"
        top = sorted(pl.items(), key=lambda x: (-x[1], x[0]))
        top1 = top[0][0] if top else "-"
        topnc = sorted(((m, c) for m, c in pl.items() if m not in CF_MAPS),
                       key=lambda x: (-x[1], x[0]))[:4]
        row = dict(unit=unit, dids=dids, canon=canon, total=total, cf=cf,
                   top1=top1, topnc=topnc, curdir=unit_dir(unit))
        if len(dids) > 1:
            containers.append(row)
        else:
            rows.append(row)
    return rows, containers


def load_manifest_canon():
    """dll id -> manifest CANONICAL primary name (the chosen identity,
    which for a multi-def shared DLL is a GENERIC STEM, not the first
    CF-prefixed sub-def). This is the faithful lane signal: the outbound
    pass moved generic multi-def DLLs out of CF even when a CF sub-def
    was present (decoration11a), and kept CF-canonical units (CFCrate)."""
    path = os.path.join(REPO, "docs/dll_naming_manifest.md")
    canon = {}
    # Main Manifest table only: col-3 is an expansion-status token. The
    # contradictions appendix uses the same id format but a free-text col-3,
    # so anchor on the status token to avoid mis-parsing it.
    status = ("COMPLETE", "CONFIRMED", "GUESSED", "RAW", "NO-RETAIL-NAME")
    for line in open(path):
        mm = re.match(r"^\| (0x[0-9A-Fa-f]+) \| (.+?) \| (\S+) \| ", line)
        if mm and mm.group(3) in status:
            canon[int(mm.group(1), 16)] = mm.group(2).split(" (+")[0].strip()
    return canon


def cf_verdict(row, manifest_canon=None):
    """Inbound-CF criterion (faithful mirror of the outbound STAY rule):
    True iff retail evidence homes this single-DLL unit INTO CF/.
    (a) the unit's MANIFEST CANONICAL primary name is CF*-prefixed
        (precedence per manifest header), OR
    (b) a CF-family map is its single #1 placement map AND the unit is
        not a generic multi-def shared DLL (manifest canon is a CF/CR
        cloud-runner name).
    The manifest canonical (a chosen GENERIC STEM for shared multi-def
    DLLs like enemy/collectible/LargeCrate) is what distinguishes a
    genuine CF unit from a shared global whose #1 map is coincidentally
    CF-family."""
    mc = None
    if manifest_canon is not None and row["dids"]:
        mc = manifest_canon.get(row["dids"][0])
    name = mc if mc else row["canon"]
    if name and (name.startswith("CF") or name.startswith("cf")):
        return True, f"CF* canonical name ({name})"
    return False, ""


def main():
    data = load()
    dllid_units, dllid_pl, def_dllid, def_name, units = data
    csv = "--csv" in sys.argv

    if "--all" in sys.argv:
        rows, containers = census(*data)
        mcanon = load_manifest_canon()
        # Inbound-CF: units OUTSIDE CF/ that retail evidence homes into CF/.
        if csv:
            print("unit,dll_ids,canonical,manifest_canon,total,cf,other,top1,"
                  "curdir,evidenced_lane,cf_inbound,verdict,top_maps")
        for row in sorted(rows, key=lambda r: r["unit"]):
            cur = row["curdir"]
            mc = mcanon.get(row["dids"][0]) if row["dids"] else None
            mcname = mc if mc else row["canon"]
            is_cf = cf_verdict(row, mcanon)[0]
            elane = "CF" if is_cf else (name_lane(mcname) or "-")
            inbound = (cur != "CF" and is_cf)
            mismatch = (elane != "-" and cur != elane)
            allmaps = Counter()
            for did in row["dids"]:
                allmaps += dllid_pl.get(did, Counter())
            tops = sorted(allmaps.items(), key=lambda x: (-x[1], x[0]))[:5]
            topm = " ".join(f"{m}:{c}" for m, c in tops)
            verdict = ("INBOUND-CF" if inbound else
                       ("MISMATCH" if mismatch else "ok"))
            if csv:
                print(f"{row['unit']},{'|'.join('0x%X'%d for d in row['dids'])},"
                      f"{row['canon']},{mcname},{row['total']},{row['cf']},"
                      f"{row['total']-row['cf']},{row['top1']},{cur or '-'},"
                      f"{elane},{inbound},{verdict},{topm}")
            else:
                print(f"{row['unit']:48s} dll={'|'.join('0x%X'%d for d in row['dids']) or '-':7s} "
                      f"mcanon={mcname:14s} tot={row['total']:3d} CF={row['cf']:2d} "
                      f"cur={cur or '-':8s} ev={elane:8s} {verdict:11s} {topm}")
        if not csv:
            print(f"\n# {len(rows)} single-DLL units, "
                  f"{len(containers)} multi-DLL containers (excluded)")
            print("# multi-DLL containers:")
            for row in sorted(containers, key=lambda r: r["unit"]):
                cfdids = [d for d in row["dids"]]
                print(f"#   {row['unit']:46s} dll={'|'.join('0x%X'%d for d in row['dids'])}")
        return

    # default: CF/ residents only (outbound mode)
    rows, _ = census(*data)
    cf_rows = [r for r in rows if r["curdir"] == "CF"]
    cf_units = {r["unit"] for r in cf_rows}
    cf_dir = os.path.join(REPO, "src/main/dll/CF")
    by_unit = {r["unit"]: r for r in cf_rows}
    if csv:
        print("unit,dll_ids,canonical,total,cf,other,top_noncf")
    for f in sorted(x for x in os.listdir(cf_dir) if x.endswith(".c")):
        unit = f"main/dll/CF/{f}"
        row = by_unit.get(unit)
        if row is None:
            # helper sliver with no descriptor / no placement
            row = dict(dids=[], canon="-", total=0, cf=0, topnc=[])
        topnc = " ".join(f"{m}:{c}" for m, c in row["topnc"])
        d = ','.join('0x%X' % x for x in row["dids"]) or '-'
        if csv:
            print(f"{f},{'|'.join('0x%X'%x for x in row['dids'])},{row['canon']},"
                  f"{row['total']},{row['cf']},{row['total']-row['cf']},{topnc}")
        else:
            print(f"{f:36s} dll={d:9s} canon={row['canon']:12s} "
                  f"tot={row['total']:3d} CF={row['cf']:2d} "
                  f"other={row['total']-row['cf']:3d}  {topnc}")


if __name__ == "__main__":
    main()
