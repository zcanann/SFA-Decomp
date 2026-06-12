#!/usr/bin/env python3
"""CF/ lane-homing audit: retail romlist placement census per CF DLL unit.

Re-homes every src/main/dll/CF/ unit from retail TRUTH (not drift-era
donor-file inheritance). Decompresses every <map>.romlist.zlb from the
retail ISO, reverse-maps placement records -> def -> handling DLL id ->
text-fn range -> splits.txt unit, then censuses each unit's placements
across maps and classifies CF-family (Cloud-Runner-Fortress) vs other.

Offsets (v1.0 USA, GSAE01): see CLAUDE.md "Retail-ISO forensics".
Usage: python3 tools/cf_lane_homing.py [--csv]
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

    return dllid_units, dllid_pl, def_dllid, def_name


def main():
    dllid_units, dllid_pl, def_dllid, def_name = load()
    unit_dllids = defaultdict(set)
    for did, us in dllid_units.items():
        for u in us:
            unit_dllids[u].add(did)
    order = defaultdict(list)
    for di in sorted(def_dllid):
        order[def_dllid[di]].append(def_name[di])

    csv = "--csv" in sys.argv
    cf_dir = os.path.join(REPO, "src/main/dll/CF")
    if csv:
        print("unit,dll_ids,canonical,total,cf,other,top_noncf")
    for f in sorted(x for x in os.listdir(cf_dir) if x.endswith(".c")):
        dids = sorted(unit_dllids.get(f"main/dll/CF/{f}", set()))
        pl = Counter()
        for did in dids:
            pl += dllid_pl.get(did, Counter())
        total = sum(pl.values())
        cf = sum(pl[m] for m in pl if m in CF_MAPS)
        canon = order[dids[0]][0] if dids and order.get(dids[0]) else "-"
        top = sorted(((m, c) for m, c in pl.items() if m not in CF_MAPS),
                     key=lambda x: -x[1])[:4]
        topnc = " ".join(f"{m}:{c}" for m, c in top)
        if csv:
            print(f"{f},{'|'.join('0x%X' % d for d in dids)},{canon},{total},{cf},{total - cf},{topnc}")
        else:
            print(f"{f:36s} dll={','.join('0x%X' % d for d in dids) or '-':9s} "
                  f"canon={canon:12s} tot={total:3d} CF={cf:2d} other={total - cf:3d}  {topnc}")


if __name__ == "__main__":
    main()
