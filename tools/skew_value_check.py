#!/usr/bin/env python3
"""Detector for THE SKEWED LABEL THAT RESOLVES -- a correctness bug no gate sees.

A Ghidra-provenance label can carry a SKEWED address and still name a real symbol.
Then:
  - dangling_extern_check is blind: nothing dangles, the name resolves.
  - fuzzy is blind: it does not compare reloc TARGETS.
  - the DOL sha1 gate is blind: placeholder-bearing units are not linked.
lightmap's FUN_8005d018 read 3.0e-05 and 5.3e-37 as aspect ratios; the true values
(1.7777778, 1.3333334) sat at exactly -0xC80 / -0xC60.

THE SKEW IS PER-SECTION -- measure it, never assume:
    .sbss = .sdata2 = 0xC80 | .sdata = .bss = 0xC60 | .data = 0xC58
(.bss derived jul17 w21 L2 from the graduated twin
 DAT_8038ee3c -> gNewShadowFrameTextures; .data from the GXNtsc480Prog seed.)

WHERE IT CAN LIVE: only in ungraduated PLACEHOLDER functions -- a reference from a
graduated function is covered by sda_reloc_check against the retail object. So
    placeholders(U) = nm(our U.o) T-list  MINUS  nm(retail U.o) T-list
and only ~29 files tree-wide have any. A label used ONLY from placeholders is
unverified by every gate.

THE ORACLES (either one promotes a finding to PROVEN):
 1. RETAIL-REFERENCE -- the strongest, and needs no twin. If addr-skew is
    referenced by the RETAIL object of the same unit while addr itself is
    referenced by NOBODY in the whole retail tree, the label is skewed: that
    address is no unit's pool. This is what caught newshadows' last 9, and what
    CLEARS skeetla's pi/32768.0 (referenced by retail skeetla.o + 5 sibling DLLs).
 2. GRADUATED TWIN -- the graduated twin in the same file. These placeholders are dead Ghidra
duplicates of functions the file already graduated, so the twin is a statement-level
answer key. If addr-skew lands on a symbol the twin actually uses -> PROVEN.

VALUE-SANITY is a WEAK secondary tell -- poor recall (a skewed label often holds a
plausible value: 410.0 sat where 1.7777778 belonged) but good precision as a
REJECTION filter (skeetla's pi / 32768.0 are obviously right, so their skew targets
0.0 / 176.0 are not). Reported alongside, never relied on alone.

WIDTH RULE: the TRUE symbol's declared size must be >= the width our C reads it at.
size < width means the load overruns its own symbol -- unambiguously wrong (rejects
gTitleScreenCreditDelay read u32 -> lbl_803DCD28 size:0x1). size > width is
AMBIGUOUS (merged atom) and is accepted; the skewed side's OWN size is never used,
it is exactly what the importer got wrong.

Usage: python3 tools/skew_value_check.py [--all]   (--all also lists SUSPECT)
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sda_reloc_check import Elf

REPO = Path(__file__).resolve().parent.parent
VER = "GSAE01"
NM = REPO / "build/binutils/powerpc-eabi-nm"
DOL = REPO / f"orig/{VER}/sys/main.dol"
SYMS = REPO / f"config/{VER}/symbols.txt"

SKEW = {".sbss": 0xC80, ".sdata2": 0xC80, ".sdata": 0xC60, ".bss": 0xC60,
        ".data": 0xC58}
CW = dict(f32=4, float=4, u32=4, s32=4, int=4, long=4, f64=8, double=8, u16=2,
          s16=2, u8=1, s8=1, char=1)


def load_dol():
    d = DOL.read_bytes()
    offs = struct.unpack(">18I", d[0:72])
    addrs = struct.unpack(">18I", d[72:144])
    sizes = struct.unpack(">18I", d[144:216])
    return [(a, s, d[o:o + s]) for o, a, s in zip(offs, addrs, sizes) if a and s]


SECS = load_dol() if DOL.is_file() else []


def f32(addr):
    for a, s, blob in SECS:
        if a <= addr and addr + 4 <= a + s:
            return struct.unpack(">f", blob[addr - a:addr - a + 4])[0]
    return None


def load_symbols():
    byname, byaddr = {}, {}
    for line in SYMS.read_text(errors="replace").splitlines():
        m = re.match(r"^(\S+)\s*=\s*([\w.]+):(0x[0-9A-Fa-f]+)(.*)$", line.strip())
        if not m:
            continue
        attrs = dict(re.findall(r"(\w+):(\S+?)(?:[;\s]|$)", m.group(4)))
        attrs["section"] = m.group(2)
        addr = int(m.group(3), 16)
        byname[m.group(1)] = (addr, attrs)
        byaddr.setdefault(addr, []).append(m.group(1))
    return byname, byaddr


def tlist(o):
    try:
        r = subprocess.run([str(NM), str(o)], capture_output=True, text=True,
                           timeout=60)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return {p[2] for p in (l.split() for l in r.stdout.splitlines())
            if len(p) == 3 and p[1] in ("T", "t")}


def und_syms(path):
    """UND symbols of an object = what it references externally."""
    return {n for (n, shndx, _v, _s, _b) in Elf(str(path)).symbols() if n and not shndx}


_RETAIL_REFS = None


def retail_refs():
    """symbol name -> [retail objects referencing it], whole tree. Built once."""
    global _RETAIL_REFS
    if _RETAIL_REFS is None:
        _RETAIL_REFS = {}
        for o in (REPO / f"build/{VER}/obj").rglob("*.o"):
            try:
                names = und_syms(o)
            except Exception:
                continue
            rel = str(o.relative_to(REPO / f"build/{VER}/obj"))
            for n in names:
                _RETAIL_REFS.setdefault(n, []).append(rel)
    return _RETAIL_REFS


FNDEF = re.compile(r"^[A-Za-z_][\w \t*]*?\b(\w+)\s*\([^;]*$", re.M)


def fn_spans(lines):
    out, i = [], 0
    while i < len(lines):
        m = FNDEF.match(lines[i])
        if m and not lines[i].lstrip().startswith(("//", "#", "extern", "return")):
            j, depth, started = i, 0, False
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                started |= "{" in lines[j]
                if started and depth <= 0:
                    break
                j += 1
            if started:
                out.append((m.group(1), i + 1, j + 1))
                i = j
        i += 1
    return out


DECL = re.compile(r"\bextern\s+(?:const\s+)?(?:volatile\s+)?"
                  r"(\w+)\s+([A-Za-z_][\w$]*)\s*(?:\[[^\]]*\])?\s*;")
IDENT = re.compile(r"\b([A-Za-z_][\w$]*)\b")


def scan():
    byname, byaddr = load_symbols()
    findings = []
    for src in sorted(REPO.glob("src/**/*.c")):
        rel = src.relative_to(REPO / "src")
        robj = REPO / f"build/{VER}/obj" / rel.with_suffix(".o")
        oobj = REPO / f"build/{VER}/src" / rel.with_suffix(".o")
        if not robj.is_file() or not oobj.is_file():
            continue
        rt, ot = tlist(robj), tlist(oobj)
        if rt is None or ot is None:
            continue
        ph, grad = ot - rt, ot & rt
        if not ph:
            continue
        lines = src.read_text(errors="replace").split("\n")
        spans = fn_spans(lines)
        ph_s = [s for s in spans if s[0] in ph]
        gr_s = [s for s in spans if s[0] in grad]
        if not ph_s:
            continue
        gr_syms = set()
        for _, a, b in gr_s:
            for ln in lines[a - 1:b]:
                gr_syms.update(IDENT.findall(ln))
        # read-width per label, from its C declaration anywhere in the file
        cwidth = {}
        for i, ln in enumerate(lines):
            m = DECL.search(ln)
            if m and m.group(1) in CW:
                cwidth[m.group(2)] = CW[m.group(1)]
        # candidates: every symbol USED inside a placeholder body
        used = {}
        for _, a, b in ph_s:
            for i in range(a - 1, min(b, len(lines))):
                if DECL.search(lines[i]):
                    continue
                for nm in IDENT.findall(lines[i]):
                    if nm in byname:
                        used.setdefault(nm, []).append(i + 1)
        for name, ls in sorted(used.items()):
            # a graduated reference means sda_reloc_check already covers it
            if any(re.search(rf"\b{re.escape(name)}\b", lines[i - 1])
                   for _, a, b in gr_s for i in range(a, min(b + 1, len(lines) + 1))):
                continue
            addr, attrs = byname[name]
            skew = SKEW.get(attrs.get("section"))
            w = cwidth.get(name)
            if not skew or not w:
                continue
            ta = addr - skew
            tn = [n for n in byaddr.get(ta, [])
                  if "size" in byname[n][1] and int(byname[n][1]["size"], 16) >= w]
            if not tn:
                continue
            twin = [n for n in tn if n in gr_syms]
            # ORACLE 1: retail references the TARGET from this very unit, and
            # references OUR label from nowhere at all.
            rr = retail_refs()
            robj_rel = str(robj.relative_to(REPO / f"build/{VER}/obj"))
            byretail = (not rr.get(name)
                        and any(robj_rel in rr.get(n, []) for n in tn))
            why = (["retail"] if byretail else []) + (["twin"] if twin else [])
            findings.append(dict(file=str(rel), name=name, addr=addr, lines=ls,
                                 sect=attrs["section"], val=f32(addr), ta=ta,
                                 tval=f32(ta), tnames=tn, twin=twin, why=why,
                                 conf="PROVEN" if why else "SUSPECT"))
    return findings


if __name__ == "__main__":
    show_all = "--all" in sys.argv
    f = scan()
    f.sort(key=lambda r: (r["conf"] != "PROVEN", r["file"], r["name"]))
    npro = sum(1 for r in f if r["conf"] == "PROVEN")
    print(f"{npro} PROVEN (retail-reference and/or twin oracle), "
          f"{len(f) - npro} SUSPECT (no oracle -- judge by value)\n")
    for r in f:
        if r["conf"] != "PROVEN" and not show_all:
            continue
        tag = r["conf"] + (f" via {'+'.join(r['why'])}" if r["why"] else "")
        print(f"[{tag}] {r['file']}  {r['name']} [{r['sect']}] "
              f"@0x{r['addr']:08X} = {r['val']!r}")
        print(f"        placeholder-only uses at {r['lines']}")
        print(f"        -0x{SKEW[r['sect']]:X} -> 0x{r['ta']:08X} = {r['tval']!r} "
              f"as {r['tnames']}"
              + (f"  <-- TWIN USES {r['twin']}" if r["twin"] else ""))
    if not show_all and len(f) - npro:
        print(f"\n({len(f) - npro} SUSPECT hidden; --all to list)")
