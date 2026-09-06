"""Rank NonMatching units by REAL RESIDUAL BYTES -- what mwld still has to reconcile.

`report.json` `fuzzy_match_percent` is the project's match-percentage truth, but
it is blind to emission ORDER, `.data` layout and pool naming, so it is the wrong
worklist for deciding which unit is closest to linking clean.  This tool screens
our `.o` against the retail `.o` over raw section bytes plus the full relocation
list, applying only the normalisations that genuine link-equivalence permits:

  1. locally-defined reloc targets canonicalise to (section, value+addend), so
     anonymous `@N` pool symbols compare equal to retail's named `lbl_` ones;
  2. external reloc targets canonicalise to their linked DOL address, so
     `gFooHi+4` and `gFooLo+0` -- literally the same address after link --
     compare equal;
  3. `.text` reloc offsets round down to the containing instruction word, since
     MWCC records a halfword reloc two bytes into the instruction dtk names by
     its word address;
  0. `.text` compares FUNCTION-ALIGNED: every retail function against our copy
     of the SAME symbol, summing the per-function differing bytes.  Comparing
     `.text` at absolute section offsets let a single short function shift every
     byte behind it, so the entire tail of the section counted as residual --
     the absolute figure mostly ranked WHERE in `.text` the first size defect
     sat, not how much was wrong (engine/0 read 56874 absolute against 3166
     function-aligned, player.c 88171 against 10018).  The absolute figure stays
     in the `abs` column and in `[abs N]` per section.  `.text` reloc OFFSETS
     canonicalise the same way, to (owning function, offset within it), for the
     same reason;
  0b. INSIDE a function the two instruction streams are ALIGNED as well, by the
     least-bytes edit distance of `align()`, and only genuinely differing
     instructions plus the insert/delete cost are charged.  Function-aligning
     fixed the section level but left exactly the same distortion one level
     down: a positional comparison inside a length-differing function charges
     every byte after the insertion point, so ONE extra instruction in an
     80-instruction function read as 182 residual bytes while objdiff scored
     that function 98.5%.  That inflated the top of the ranking with
     length-differing units and made `fix the length' look like an enormous win
     when it can cost fuzzy -- several lanes were sent at units that were never
     as bad as they looked (Hcurves 3926 -> 149, and it is one 3-instruction
     function; track_dolphin 4369 -> 613; player.c 10003 -> 1177; expgfx
     6906 -> 428).  Against objdiff's own per-function `fuzzy_match_percent`
     the two now broadly agree where before they diverged wildly: over the 58
     length-differing functions the mean gap between the residual-implied
     percentage and objdiff's fell from 40.3 points to 2.6, the median from
     39.3 to 1.0.  A genuine size difference is still charged, as the alignment's
     insert/delete cost, and is reported whole in the `dlen` column and per
     section as `<dlen N>`, because it still has to be fixed before the unit can
     link clean;
  3b. a reloc TARGETING `.text` canonicalises to (containing function, offset
     within that function) rather than to a raw `.text` section offset.  A
     function-pointer table entry names a function, not an address: mwld
     resolves it to wherever that function lands, so the entry is link-identical
     to retail's whenever it names the same function at the same intra-function
     offset.  Comparing raw section offsets instead made every such reloc flip
     the moment ANY earlier function in our `.text` differed in size -- a whole
     `.data` jumptable reported as residual on the strength of one unrelated
     `.text` byte, double-counting a defect the `.text` column already carries.
     Only `.text` targets get this; `.data`/`.rodata`/`.sdata2` targets keep
     comparing by absolute offset, because for those sections the layout IS the
     linked image and a shifted target is a real difference;
  4. static functions we define that retail's `.o` lacks are excised (mwld
     dead-strips unreferenced statics, so they can never appear in a
     dtk-reconstructed object), and every reloc offset and `.text`-targeting
     reloc value is remapped through that excision;
  5. trailing all-zero alignment padding is excluded;
  6. relocations compare as SETS, so the order in which a `.rela` section lists
     them is inert.  mwld consumes a relocation section as an unordered pool, so
     the order MWCC emits in versus the offset-sorted order dtk reconstructs is
     not a difference at all.

Everything else -- code emission order, `.data` layout, section content and size
-- is counted, because all of it changes the linked image.

CALIBRATION.  Every unit `report.json` marks `complete` is provably link-equal,
because dtk gates the DOL sha1 on it.  The screen must therefore report zero
residual for all of them, and `rank` prints that count.  It currently reads 8
out of 998 (99.2% clean), all of them SDK/library units rather than game code:
OS.c, OSExec.c and synth_seq_queue.c have residual only because their retail
`.o` carries no `.text` at all, an attribution artifact (function-aligned they
read 0, 14 and 0 bytes); OSTime.c, voice_id.c, ARWArwing.c, mtx.c and
__exception.s leave a handful of bytes each.  Treat that set as the screen's
known noise floor.  If the count grows after a toolchain or config change, the
screen -- not the units -- is what regressed.  Note the noise floor is measured
on the ABSOLUTE figure, because link-equality is byte-equality including layout;
the function-aligned figure is the worklist, not the flip test.  That is also
what makes the floor a usable regression gate on the screen itself: turning the
intra-function alignment on left it at the same 8 units out of 998, with the
link-clean count unchanged at 880 and the differing count unchanged at 118 --
alignment may only ever LOWER a residual (positional comparison is itself one
particular alignment, so `align()` takes it as an upper bound), so no unit can
cross the zero boundary in either direction.

The report-to-config key normalisation has to cope with two shapes dtk emits:
`metadata.module_name` is absent for some units (their `main/` prefix has to be
stripped by matching against the known module names instead), and the report
strips every source suffix, not just `.c`.  Getting either wrong silently
defaults the unit to NonMatching and manufactures phantom flip candidates --
`__start.c`, `__mem.c`, `mem_TRK.c`, `__init_cpp_exceptions.cpp` and
`targsupp.s` were all reported as link-clean flip candidates while already
being `complete`.

ZERO RESIDUAL IS NECESSARY, NOT SUFFICIENT.  `rank` splits its zero-residual
units into flip candidates and a BLOCKED list.  A blocked unit is byte- and
relocation-equal but its retail `.o` exports a global name ours does not --
invariably a `lbl_` pool constant, which MWCC emits as an anonymous local `@N`
-- AND some sibling still on its retail object actually references that name.
Both halves are required.  The screen used to test only the first and parked
`dlls/engine/73` over 31 names nothing in the image consumed; intersecting the
missing exports against the undefined references of the objects mwld is really
given (`consumers`, read off the generated link rule) cleared it, and it
flipped with the DOL byte-identical. The former gametext fragments illustrated
this shape: retail gametext_tail/textrender objects carried real undefined
references to `lbl_803DE6F0`/`lbl_803DE6F8`. They are now reunited in gametext.c,
with the compiler emitting their shared pool. Names missing but unconsumed are
printed alongside the flip candidate as harmless, so the distinction stays
visible rather than being silently dropped.

WARNING.  Residual and `fuzzy_match_percent` can move in OPPOSITE directions: a
change may cut residual while regressing fuzzy.  Only a change that drives
residual to zero flips a unit to `complete`; anything short of that must not
regress fuzzy.  Always regenerate `report.json` and read both numbers before
believing a win.

Subcommands
    rank [unit ...]     residual ranking, largest-first, with calibration trailer
    where <unit>        locate the residual: which function, which instruction
    classify            split residuals into REGROT (allocator/coloring caps)
                        vs STRUCT (different instruction sequence -- attackable)
    order               units whose functions are a PERMUTATION of retail's
                        order: the target of the emission-order lever
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

ROOT = Path(os.environ.get("SFA_ROOT", Path(__file__).resolve().parents[1]))
OBJDUMP = ROOT / "build/binutils/powerpc-eabi-objdump"
SECS = [".text", ".data", ".rodata", ".sdata", ".sdata2", ".sbss", ".bss",
        ".ctors", ".dtors", ".init", ".extab", ".extabindex"]
SYMRE = re.compile(r"^\s*(\S+)\s*=\s*\S*?:?(0x[0-9A-Fa-f]+)")
REG = re.compile(r"\br\d+\b|\bf\d+\b|\bcr\d+\b")

GADDR = {}
for _p in sorted(ROOT.glob("config/GSAE01/**/symbols.txt")):
    for _line in open(_p, errors="ignore"):
        _m = SYMRE.match(_line)
        if _m:
            GADDR.setdefault(_m.group(1), int(_m.group(2), 16))


def load(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sname = {i: s.name for i, s in enumerate(elf.iter_sections())}
        data, statics, names, funcs = {}, [], {}, []
        for sec in elf.iter_sections():
            if sec.name in SECS:
                data[sec.name] = (b"\0" * sec["sh_size"]
                                  if sec["sh_type"] == "SHT_NOBITS" else sec.data())
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for s in sec.iter_symbols():
                sh = s["st_shndx"]
                if not isinstance(sh, int):
                    continue
                sn = sname.get(sh)
                if sn not in SECS or not s.name:
                    continue
                names.setdefault(sn, set()).add(s.name)
                if sn == ".text" and s["st_info"]["type"] == "STT_FUNC":
                    funcs.append((s["st_value"], s["st_size"], s.name))
                    if s["st_size"] and s["st_info"]["bind"] == "STB_LOCAL":
                        statics.append((s.name, s["st_value"], s["st_size"]))
        rel = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            tgt = sname.get(sec["sh_info"])
            if tgt not in SECS:
                continue
            st = elf.get_section(sec["sh_link"])
            for r in sec.iter_relocations():
                sym = st.get_symbol(r["r_info_sym"])
                add = r["r_addend"] if "r_addend" in r.entry else 0
                sh = sym["st_shndx"]
                tsec = sname.get(sh) if isinstance(sh, int) else None
                rel.setdefault(tgt, []).append(
                    (r["r_offset"], r["r_info_type"], tsec,
                     sym["st_value"], sym.name, add))
        return data, statics, names, rel, funcs


def fn_at(funcs):
    """Map a `.text` offset to (containing function, offset within it)."""
    tab = sorted(set(funcs))
    starts = [f[0] for f in tab]

    def lookup(v):
        import bisect
        i = bisect.bisect_right(starts, v) - 1
        while i >= 0:
            st, sz, nm = tab[i]
            end = st + sz if sz else (starts[i + 1] if i + 1 < len(tab) else None)
            if end is None or v < end:
                return (nm, v - st)
            i -= 1
        return None
    return lookup


def fn_spans(funcs, size):
    """name -> (start, end) byte span of each function body in `.text`."""
    tab = sorted(set(funcs))
    out = {}
    for i, (v, sz, nm) in enumerate(tab):
        end = v + sz if sz else (tab[i + 1][0] if i + 1 < len(tab) else size)
        out.setdefault(nm, (v, min(end, size)))
    return out


def words(b):
    """`.text` bytes as big-endian instruction words (trailing odd bytes kept)."""
    n = len(b) & ~3
    return [int.from_bytes(b[i:i + 4], "big") for i in range(0, n, 4)]


def _brel(w):
    """(displacement in words, alignment key) for a PC-relative branch, else None.

    A relative branch encodes a byte displacement, so inserting one instruction
    ahead of it changes its bytes without changing what it means.  The key masks
    the displacement out so alignment is not derailed by it; the displacement is
    returned so the comparison can ask the real question -- does the branch land
    on the same instruction? -- instead of comparing raw bytes.
    """
    op = w >> 26
    if w & 2:                       # AA=1: absolute target, not position-relative
        return None
    if op == 18:                    # b / bl
        d = w & 0x03FFFFFC
        if d & 0x02000000:
            d -= 0x04000000
        return d >> 2, w & 0xFC000003
    if op == 16:                    # bc / bcl
        d = w & 0x0000FFFC
        if d & 0x8000:
            d -= 0x10000
        return d >> 2, w & 0xFFFF0003
    return None


def _key(w):
    r = _brel(w)
    return r[1] if r else w


INF = 1 << 30


def _bh(x, y):
    """Byte hamming distance of two instruction words."""
    z = x ^ y
    if not z:
        return 0
    return ((z >> 24) & 255 != 0) + ((z >> 16) & 255 != 0) \
        + ((z >> 8) & 255 != 0) + (z & 255 != 0)


def align(a, b, band=48):
    """Least-BYTES alignment of two instruction-word sequences.

    Residual is a count of bytes, so the honest question is `what is the
    smallest number of bytes that have to change to turn our function into
    retail's', with an inserted or deleted instruction costing its four bytes.
    That is a weighted edit distance -- substitution priced at the byte hamming
    distance of the two words, insert and delete at 4 -- and it is computed
    here by Wagner-Fischer restricted to a diagonal band.

    Minimising bytes rather than edits matters.  A plain LCS diff (Myers, or
    difflib) minimises insertions plus deletions, so it will happily pay two
    indels -- eight bytes -- to avoid one substitution that costs four or less,
    and on a REORDERING it charges the moved instructions twice.  Positional
    comparison is itself just one particular alignment (all substitutions), so
    the banded optimum is never worse than it: `resid' can only fall when the
    alignment is turned on, never rise.  The band is |n-m| wide plus a margin,
    which covers every realistic codegen difference; the caller still takes the
    min against the positional cost so a clipped band can never inflate.
    """
    n, m = len(a), len(b)
    d = m - n
    lo, hi = min(0, d) - band, max(0, d) + band
    w = hi - lo + 1
    back = bytearray((n + 1) * w)
    prev = [INF] * w
    o0 = -lo                                   # offset of j == i
    if 0 <= o0 < w:
        prev[o0] = 0
    for o in range(o0 + 1, w):
        j = o + lo
        if j > m:
            break
        prev[o] = 4 * j
        back[o] = 2
    for i in range(1, n + 1):
        cur = [INF] * w
        base = i * w
        for o in range(w):
            j = i + lo + o
            if j < 0:
                continue
            if j > m:
                break
            best, ch = INF, 0
            if j == 0:
                best, ch = prev[o + 1] + 4 if o + 1 < w else INF, 1
                if best >= INF:
                    continue
            else:
                s = prev[o]
                if s < INF:
                    best, ch = s + _bh(a[i - 1], b[j - 1]), 3
                if o + 1 < w and prev[o + 1] + 4 < best:
                    best, ch = prev[o + 1] + 4, 1
                if o and cur[o - 1] + 4 < best:
                    best, ch = cur[o - 1] + 4, 2
            cur[o] = best
            back[base + o] = ch
        prev = cur
    o = m - n - lo
    if not (0 <= o < w) or prev[o] >= INF:
        return None, None
    return prev[o], _trace(back, n, m, lo, w)


def _trace(back, n, m, lo, w):
    """Walk the choice table back into difflib-style opcodes."""
    path, i, j = [], n, m
    while i or j:
        ch = back[i * w + (j - i - lo)]
        if ch == 3:
            i -= 1
            j -= 1
            path.append(("sub", i, j))
        elif ch == 1:
            i -= 1
            path.append(("del", i, j))
        elif ch == 2:
            j -= 1
            path.append(("ins", i, j))
        else:
            break
    path.reverse()
    ops, i, j, p = [], 0, 0, 0
    while p < len(path):
        if path[p][0] == "sub":
            s = p
            while p < len(path) and path[p][0] == "sub":
                p += 1
            c = p - s
            ops.append(("pair", i, i + c, j, j + c))
            i += c
            j += c
            continue
        nd = ni = 0
        while p < len(path) and path[p][0] != "sub":
            if path[p][0] == "del":
                nd += 1
            else:
                ni += 1
            p += 1
        ops.append(("replace" if nd and ni else "delete" if nd else "insert",
                    i, i + nd, j, j + ni))
        i += nd
        j += ni
    return ops


def fn_resid(a, b, detail=False):
    """Differing bytes between two copies of one function, counted over an
    ALIGNED instruction diff rather than positionally.

    Positional comparison charges every byte behind an insertion point: a single
    extra instruction in an 80-instruction function reads as 182 residual bytes
    while objdiff scores that same function 98.5%.  That inflation is not a
    rounding error -- it re-ranks the whole worklist by WHERE a length defect
    sits rather than how much is wrong, and it makes `fixing the length' look
    like a huge win when it can cost fuzzy.

    So the two instruction streams are aligned the way objdiff aligns them (a
    diff/LCS over decoded instructions) and only real differences are charged:
    the differing bytes of instructions the alignment pairs up, plus four bytes
    for each instruction inserted or deleted.  Relative branches compare by
    where they LAND -- our target index mapped through the alignment against
    retail's -- so a branch whose displacement moved only because the function
    got longer is not charged a second time for the insertion.
    """
    wa, wb = words(a), words(b)
    ta, tb = a[len(wa) * 4:], b[len(wb) * 4:]
    tail = sum(1 for x, y in zip(ta, tb) if x != y) + abs(len(ta) - len(tb))
    pos = (sum(_bh(x, y) for x, y in zip(wa, wb))
           + 4 * abs(len(wa) - len(wb)) + tail)
    if wa == wb and not tail:
        return (0, []) if detail else 0
    ka, kb = [_key(w) for w in wa], [_key(w) for w in wb]
    _, ops = align(ka, kb)
    if ops is None:
        m = min(len(wa), len(wb))
        ops = [("pair", 0, m, 0, m)]
        if len(wa) > m:
            ops.append(("delete", m, len(wa), m, m))
        elif len(wb) > m:
            ops.append(("insert", m, m, m, len(wb)))
    amap = {}
    for tag, i1, i2, j1, j2 in ops:
        if tag == "pair":
            for k in range(i2 - i1):
                amap[i1 + k] = j1 + k
    n = 0
    sites = []
    for tag, i1, i2, j1, j2 in ops:
        if tag == "pair":
            for k in range(i2 - i1):
                i, j = i1 + k, j1 + k
                if wa[i] == wb[j]:
                    continue
                ra, rb = _brel(wa[i]), _brel(wb[j])
                if ra and rb and amap.get(i + ra[0], -1) == j + rb[0]:
                    continue        # same landing instruction, shifted encoding
                n += _bh(wa[i], wb[j])
                sites.append(("sub", i, i + 1, j, j + 1))
            continue
        m = min(i2 - i1, j2 - j1)
        for k in range(m):
            n += _bh(wa[i1 + k], wb[j1 + k])
        n += 4 * ((i2 - i1) + (j2 - j1) - 2 * m)
        sites.append((tag, i1, i2, j1, j2))
    n = min(n + tail, pos)
    return (n, sites) if detail else n


def text_fn_resid(ao, at, fo, ft):
    """Differing bytes counted FUNCTION-ALIGNED: every retail function against
    OUR copy of the same symbol, each pair compared by `fn_resid`.

    Comparing `.text` at absolute section offsets makes one short function shift
    every byte behind it, so the whole tail of the section counts as residual --
    the absolute figure mostly ranks WHERE in `.text` the first size defect sits,
    not how much is actually wrong.  Matching by symbol first isolates each
    defect to the function that owns it; aligning inside the function stops the
    same inflation recurring one level down.  A genuine size difference is still
    charged, as the insert/delete cost of the alignment, and is also reported
    whole in the `dlen` column, because it is still a defect that has to be
    fixed before the unit can link clean.  Bytes of a retail function our object
    does not define at all are returned separately and printed as `<miss N>`:
    that is missing CONTENT (typically a `gap_` region dtk attributes to this
    unit but no source provides), a different -- and usually not
    source-attackable -- work class from a byte-level codegen defect.  render.c
    is 4876 of its 6711 that way.
    """
    so_ = fn_spans(fo, len(ao))
    st_ = fn_spans(ft, len(at))
    nb = miss = dlen = 0
    for nm, (s, e) in st_.items():
        b = at[s:e]
        if nm not in so_:
            n = len(b) if any(b) else 0
            nb += n
            miss += n
            dlen += n
            continue
        s2, e2 = so_[nm]
        a = ao[s2:e2]
        nb += fn_resid(a, b)
        dlen += abs(len(a) - len(b))
    return nb, miss, dlen


def canon(rl, sec, remap, fnsym=None, offkey=None):
    out = []
    for off, typ, tsec, val, nm, add in rl:
        if tsec in SECS:
            t = val + add
            if tsec == ".text":
                if remap(t) is None:
                    continue
                sym = fnsym(t) if fnsym else None
                t = sym if sym is not None else ("ABS", remap(t))
            c = ("DEF", tsec, t)
        elif nm in GADDR:
            c = ("ADDR", GADDR[nm] + add)
        else:
            c = ("UND", nm, add)
        o = off
        if sec == ".text":
            if offkey:
                o = offkey(off)
            else:
                o = remap(off)
                o = None if o is None else ("ABS", o & ~3)
            if o is None:
                continue
        out.append((o, typ, c))
    return out


def text_offkey(lookup, keep):
    """A `.text` reloc offset as (owning function, offset within it).

    Same reason as the byte comparison: an absolute offset makes every reloc
    behind a size defect report as residual.  A reloc lives inside a function,
    and mwld places it wherever that function lands.
    """
    def key(off):
        r = lookup(off)
        if r is None:
            return None
        nm, d = r
        return None if nm not in keep else (nm, d & ~3)
    return key


def text_excision(bo, statics, keep):
    """Byte mask + offset remap for the statics mwld would dead-strip."""
    drop = set()
    for n, v, s in statics:
        if n in keep:
            continue
        e = v + s
        while e < len(bo) and e % 4:
            e += 1
        drop |= set(range(v, min(e, len(bo))))
    if not drop:
        return bo, (lambda x: x)
    new, k = {}, 0
    for i in range(len(bo)):
        if i in drop:
            continue
        new[i] = k
        k += 1
    new[len(bo)] = k
    return bytes(b for i, b in enumerate(bo) if i not in drop), new.get


def exports(path):
    """Global symbol names the object DEFINES -- what mwld can resolve from it."""
    out = set()
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sn = {i: s.name for i, s in enumerate(elf.iter_sections())}
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for s in sec.iter_symbols():
                sh = s["st_shndx"]
                if not isinstance(sh, int) or sn.get(sh) not in SECS:
                    continue
                if (s.name and s["st_info"]["bind"] != "STB_LOCAL"
                        and s["st_info"]["type"] != "STT_SECTION"
                        and not s.name.startswith("gap_")):
                    out.add(s.name)
    return out


def undefined(path):
    """Global names the object REFERENCES but does not define."""
    out = set()
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for s in sec.iter_symbols():
                if s["st_shndx"] == "SHN_UNDEF" and s.name:
                    out.add(s.name)
    return out


def link_objects():
    """The object list mwld is actually given, read off the generated link rule.

    That list is the ground truth for which side of each unit is in the image:
    a `complete` unit contributes `build/GSAE01/src/...`, a NonMatching one
    still contributes its retail `build/GSAE01/obj/...`.  Anything not in the
    link cannot consume a symbol and must not be allowed to block a flip.
    """
    txt = (ROOT / "build.ninja").read_text().splitlines()
    out, i = [], 0
    while i < len(txt):
        if not re.match(r"^build \S+\.elf: link ", txt[i]):
            i += 1
            continue
        buf = []
        while True:
            buf.append(txt[i].rstrip())
            if not buf[-1].endswith("$"):
                break
            i += 1
        blob = " ".join(x.rstrip("$").strip() for x in buf)
        blob = blob.split(":", 1)[1].split("|")[0]
        out += [t for t in blob.split() if t.endswith(".o")]
        i += 1
    return out


_CONSUMERS = None


def consumers():
    """name -> the linked objects with an UNDEFINED reference to it.

    This is the half the BLOCKED screen used to be missing.  `missing_exports`
    asks only whether retail's object exports a global that ours does not; it
    never asks whether anything in the link still NEEDS that global.  MWCC emits
    a pool constant as an anonymous local `@N`, so a `lbl_...` retail exports
    disappears the moment we start linking our object -- but that only breaks
    the link if some sibling still on its retail object actually references the
    name.  Screening on the export set alone parked `dlls/engine/73` over 31
    names (`gCamCombatPi`, `gCamCombatBinAngleHalfCircle`, 29 `lbl_803E18xx`)
    that NOTHING in the image referenced; it flipped clean, DOL byte-identical.
    Intersecting the missing exports against this index is what makes the
    BLOCKED verdict mean `a sibling needs this', not `retail happened to name
    it'.

    The two failure directions are not symmetric.  Over-blocking parks a
    flippable unit; under-blocking sends someone at a flip that breaks the DOL.
    So an empty or unreadable object list is treated as `no information' rather
    than as `nothing consumes anything' -- `None` here makes every missing
    export block again, which is exactly the old, conservative behaviour.
    """
    global _CONSUMERS
    if _CONSUMERS is None:
        objs = [ROOT / o for o in link_objects()]
        objs = [p for p in objs if p.exists()]
        if not objs:
            _CONSUMERS = False
            return None
        idx = {}
        for p in objs:
            for n in undefined(p):
                idx.setdefault(n, set()).add(str(p.relative_to(ROOT)))
        _CONSUMERS = idx
    return _CONSUMERS or None


def missing_exports(ours, tgt):
    """Names retail's object exports that ours does not.

    Split into (blocking, unconsumed): a missing export only blocks the flip
    when something else in the link has an undefined reference to it.  Our own
    object is excluded from the consumer set -- it resolves the name internally
    through its local `@N` -- as is retail's copy of the same unit, which
    leaves the image when the unit flips.
    """
    miss = exports(tgt) - exports(ours)
    idx = consumers()
    if not miss or idx is None:
        return miss, set()
    mine = {str(Path(ours).resolve().relative_to(ROOT.resolve())),
            str(Path(tgt).resolve().relative_to(ROOT.resolve()))}
    block = {n for n in miss if idx.get(n, set()) - mine}
    return block, miss - block


def screen(ours, tgt):
    do, so, no, ro, fo = load(ours)
    dt, st, nt, rt, ft = load(tgt)
    bo, remap = text_excision(do.get(".text", b""), so, nt.get(".text", set()))
    lo, lt = fn_at(fo), fn_at(ft)
    common = ({n for _, _, n in fo} & {n for _, _, n in ft})
    ko, kt = text_offkey(lo, common), text_offkey(lt, common)
    per, tot_b, tot_r, tot_abs, tot_dl = {}, 0, 0, 0, 0
    for sec in SECS:
        a = bo if sec == ".text" else do.get(sec, b"")
        b = dt.get(sec, b"")
        nb = 0
        if len(a) != len(b):
            n = min(len(a), len(b))
            tail = (a if len(a) > len(b) else b)[n:]
            nb = (0 if not any(tail) else len(tail))
            nb += sum(1 for i in range(n) if a[i] != b[i])
        elif a != b:
            nb = sum(1 for x, y in zip(a, b) if x != y)
        na, miss, dl = nb, 0, abs(len(a) - len(b))
        if sec == ".text":
            nb, miss, dl = text_fn_resid(do.get(".text", b""), b, fo, ft)
        nr = len(set(canon(ro.get(sec, []), sec, remap, lo, ko if sec == ".text" else None))
                 ^ set(canon(rt.get(sec, []), sec, lambda x: x, lt,
                             kt if sec == ".text" else None)))
        if nb or nr or na:
            per[sec] = (nb, nr, len(a), len(b), na, miss, dl)
            tot_b += nb
            tot_r += nr
            tot_abs += na
            tot_dl += dl
    return tot_b, tot_r, per, tot_abs, tot_dl


def fn_fuzzy(f):
    """objdiff records a UNIT's score under `measures` but a FUNCTION's at top
    level.  Reading the unit shape on a function silently scored every function
    0, so the `sub100` column counted every function in the unit."""
    m = f.get("measures")
    if isinstance(m, dict) and "fuzzy_match_percent" in m:
        return m["fuzzy_match_percent"]
    return f.get("fuzzy_match_percent", 0.0)


def units(only=()):
    cfg = json.load(open(ROOT / "build/GSAE01/config.json"))
    rep = json.load(open(ROOT / "build/GSAE01/report.json"))
    meta = {}
    modules = {m["name"] for m in cfg.get("modules", [])} | {cfg["name"]}
    for u in rep["units"]:
        mod = u["metadata"].get("module_name") or ""
        n = u["name"]
        if mod and n.startswith(mod + "/"):
            n = n[len(mod) + 1:]
        row = (u["metadata"].get("complete", False),
               u["measures"].get("fuzzy_match_percent", 0.0),
               sum(1 for f in u.get("functions", [])
                   if fn_fuzzy(f) < 100.0))
        meta[n] = row
        head = n.split("/", 1)
        if len(head) == 2 and head[0] in modules:
            meta.setdefault(head[1], row)
    for u in cfg["units"]:
        name = u["name"]
        key = re.sub(r"\.(c|cpp|cp|cxx|cc|s|S)$", "", name)
        if only and not any(o in name for o in only):
            continue
        tgt = ROOT / u["object"]
        ours = ROOT / u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
        if ours.exists() and tgt.exists():
            yield name, str(ours), str(tgt), meta.get(key, (False, 0.0, 0))


def norm_insn(t):
    """Drop absolute branch targets; the <sym+0xNN> form is already relative."""
    return t.split()[0] + " " + t[t.index("<"):] if "<" in t else t


def dis(obj, sec=".text"):
    out = subprocess.run([str(OBJDUMP), "-M", "gekko", "-drz", "-j", sec, str(obj)],
                         capture_output=True, text=True).stdout
    rows, cur = [], "?"
    for line in out.splitlines():
        if ">:" in line and line and line[0].isdigit():
            cur = line.split("<")[1].split(">")[0]
            continue
        p = line.split("\t")
        if len(p) >= 3:
            try:
                int(p[0].strip().rstrip(":"), 16)
            except ValueError:
                continue
            rows.append((cur, norm_insn(p[2].strip())))
    return rows


def fn_order(path, sec=".text"):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sn = {i: s.name for i, s in enumerate(elf.iter_sections())}
        o = []
        for s_ in elf.iter_sections():
            if isinstance(s_, SymbolTableSection):
                for s in s_.iter_symbols():
                    sh = s["st_shndx"]
                    if (isinstance(sh, int) and sn.get(sh) == sec and s.name
                            and s["st_info"]["type"] == "STT_FUNC"):
                        o.append((s["st_value"], s.name))
        return [n for _, n in sorted(set(o))]


def cmd_rank(args):
    rows = []
    for name, ours, tgt, (done, fz, s1) in units(args):
        try:
            tb, tr, per, ta, td = screen(ours, tgt)
        except Exception as e:
            print(f"ERR {name}: {e}", file=sys.stderr)
            continue
        rows.append((tb, tr, name, per, done, s1, fz, ta, td))
    rows.sort(key=lambda r: (r[0] + 4 * r[1], r[7]))
    print(f"{'resid':>8} {'dlen':>7} {'abs':>8} {'relocD':>7} {'M':>1} "
          f"{'sub100':>6} {'fuzzy':>7}  unit")
    for tb, tr, name, per, done, s1, fz, ta, td in rows:
        if not tb and not tr and not ta:
            continue
        parts = " ".join(
            f"{k}:{v[0]}b" + (f"[abs {v[4]}]" if v[4] != v[0] else "")
            + (f"<miss {v[5]}>" if v[5] else "")
            + (f"<dlen {v[6]}>" if v[6] else "")
            + (f"/{v[1]}r" if v[1] else "")
            + (f"(sz {v[2]}!={v[3]})" if v[2] != v[3] else "")
            for k, v in per.items())
        print(f"{tb:>8} {td:>7} {ta:>8} {tr:>7} {'Y' if done else '.':>1} "
              f"{s1:>6} {fz:>7.2f}  {name}\n           {parts}")
    clean = [r for r in rows if not r[0] and not r[1] and not r[7]]
    fp = [r for r in rows if (r[0] or r[1] or r[7]) and r[4]]
    print(f"\n# screened {len(rows)}  link-clean {len(clean)}  differing {len(rows)-len(clean)}")
    print(f"# CALIBRATION complete-but-differing (expect 8, all SDK no-.text units): {len(fp)}")
    for r in fp:
        print(f"    {r[0]}b[abs {r[7]}]/{r[1]}r  {r[2]}")
    bad = [r for r in clean if not r[4]]
    ready, held = [], []
    lookup = {n: (o, t) for n, o, t, _ in units(args)}
    for r in bad:
        block, free = missing_exports(*lookup[r[2]])
        (held if block else ready).append((r[2], sorted(block), sorted(free)))
    print(f"# LINK-CLEAN but NonMatching (flip candidates): {len(ready)}")
    for n, _, free in ready:
        tail = f"  (unconsumed, harmless: {' '.join(free)})" if free else ""
        print(f"    {n}{tail}")
    if held:
        print(f"# LINK-CLEAN but BLOCKED (retail object exports names ours does "
              f"not AND a linked sibling still references them): {len(held)}")
        for n, block, free in held:
            print(f"    {n}  blocking: {' '.join(block)}")
            for b in block:
                by = sorted((consumers() or {}).get(b, ()))[:4]
                print(f"        {b} <- {' '.join(by)}")


def _bysym(rows):
    out = {}
    for fn, insn in rows:
        out.setdefault(fn, []).append(insn)
    return out


def _aligned(ours, tgt):
    """Per-symbol instruction lists, so a length defect in one function cannot
    misalign every function behind it."""
    a, b = _bysym(dis(ours)), _bysym(dis(tgt))
    return {k: v for k, v in a.items() if k in b}, b


def fn_sites(ours, tgt):
    """name -> (residual bytes, alignment diff sites) per shared function."""
    do, _, _, _, fo = load(ours)
    dt, _, _, _, ft = load(tgt)
    ao, at = do.get(".text", b""), dt.get(".text", b"")
    so_, st_ = fn_spans(fo, len(ao)), fn_spans(ft, len(at))
    out = {}
    for nm, (s, e) in st_.items():
        if nm in so_:
            s2, e2 = so_[nm]
            out[nm] = fn_resid(ao[s2:e2], at[s:e], detail=True)
    return out


def cmd_where(args):
    for name, ours, tgt, _ in units(args):
        da, db = _bysym(dis(ours)), _bysym(dis(tgt))
        sites = fn_sites(ours, tgt)
        bad = [f for f in sites if sites[f][0]]
        bad.sort(key=lambda f: (-sites[f][0], f))
        tot = n = shown = 0
        for fn in bad:
            rb, ss = sites[fn]
            x, y = da.get(fn, []), db.get(fn, [])
            tot += rb
            print(f"  [{fn}] {rb}b resid  ours {len(x)} insn / retail {len(y)}")
            for tag, i1, i2, j1, j2 in ss:
                n += max(i2 - i1, j2 - j1)
                shown += 1
                if shown > 80:
                    continue
                if tag == "sub" and i2 - i1 == 1:
                    p, q = (x[i1] if i1 < len(x) else "?",
                            y[j1] if j1 < len(y) else "?")
                    kind = ("reg" if REG.sub("#", p) == REG.sub("#", q)
                            else "STRUCT")
                    print(f"      #{i1} ({kind})\n"
                          f"        ours   {p}\n        retail {q}")
                    continue
                print(f"      #{i1} ({tag.upper()} {i2-i1}->{j2-j1})")
                for p in x[i1:i2][:8]:
                    print(f"        ours   {p}")
                for q in y[j1:j2][:8]:
                    print(f"        retail {q}")
        print(f"# {name}: {len(bad)} differing functions, {n} differing "
              f"instructions after alignment, {tot} aligned residual bytes")


def fn_split(ours, tgt):
    """Per-function (reg-permutation, structural, insert/delete) instruction
    counts, over the SAME alignment the residual is charged on.

    `classify` used to run its own `difflib.SequenceMatcher` over the decoded
    instruction text.  That is a different diff from the one `fn_resid` charges,
    and it is the wrong one twice over.  LCS minimises insertions plus
    deletions, so on a pure REORDERING it pays two indels rather than one
    substitution and books the moved instructions as length defects; and any
    opcode block whose two sides differ in length at all was counted whole into
    `ln`.  Between them those two effects swept most register-permutation caps
    into the LEN bucket: the unit labels read LEN 59 / REGROT 32 / STRUCT 14
    while the same objects aligned by `align()` are 9010 permuted instructions
    against 1200 structural and 410 genuine insert/delete.  Sending a lane at a
    `LEN' unit that is really a coloring cap is the expensive kind of wrong, so
    the classification now shares `fn_sites`.

    A `sub` site whose two instructions differ only in register names is a
    coloring/allocator decision (REGROT); anything else -- a different opcode, a
    different displacement, a different immediate -- is STRUCT, the class source
    levers can actually move.  Insert/delete sites are LEN.
    """
    da, db = _bysym(dis(ours)), _bysym(dis(tgt))
    out = {}
    for fn, (rb, sites) in fn_sites(ours, tgt).items():
        if not rb:
            continue
        x, y = da.get(fn, []), db.get(fn, [])
        ro = st = ln = 0
        for tag, i1, i2, j1, j2 in sites:
            if tag == "sub" and i2 - i1 == 1:
                p = x[i1] if i1 < len(x) else "?"
                q = y[j1] if j1 < len(y) else "?"
                if REG.sub("#", p) == REG.sub("#", q):
                    ro += 1
                else:
                    st += 1
                continue
            ln += max(i2 - i1, j2 - j1)
        out[fn] = (rb, ro, st, ln)
    return out


def cmd_classify(args):
    out = []
    for name, ours, tgt, (done, fz, s1) in units(args):
        if done:
            continue
        try:
            tb, tr, _, ta, _ = screen(ours, tgt)
        except Exception:
            continue
        if not tb and not tr and not ta:
            continue
        try:
            per = fn_split(ours, tgt)
        except Exception:
            continue
        ro = sum(v[1] for v in per.values())
        st = sum(v[2] for v in per.values())
        ln = sum(v[3] for v in per.values())
        kind = ("STRUCT" if st else "LEN" if ln
                else "REGROT" if ro else "DATA")
        worst = sorted(per, key=lambda f: (-(per[f][2] + per[f][3]), f))[:3]
        out.append((tb + 4 * tr, tb, tr, kind, ro, st, ln, name, ",".join(worst)))
    out.sort()
    print(f"{'score':>7} {'resid':>7} {'relD':>5} {'kind':>6} {'reg':>5} "
          f"{'str':>5} {'len':>5}  unit")
    for s, tb, tr, k, ro, st, ln, n, f in out:
        print(f"{s:>7} {tb:>7} {tr:>5} {k:>6} {ro:>5} {st:>5} {ln:>5}  {n}"
              f"\n            {f}")
    from collections import Counter
    print("\n#", Counter(o[3] for o in out))
    print(f"# instructions: reg-permutation {sum(o[4] for o in out)}  "
          f"structural {sum(o[5] for o in out)}  "
          f"insert/delete {sum(o[6] for o in out)}")
    print("# REGROT = allocator/coloring cap.  STRUCT/LEN = different instruction"
          " sequence, the class source levers can actually move.")
    print("# A unit is labelled by its most attackable content, so a STRUCT unit"
          " may still be mostly permutation -- read the reg/str/len columns.")


def cmd_order(args):
    import difflib
    for name, ours, tgt, (done, _, _) in units(args):
        if done:
            continue
        try:
            a, b = fn_order(ours), fn_order(tgt)
        except Exception:
            continue
        a = [x for x in a if x in set(b)]
        if a != b and sorted(a) == sorted(b):
            print(f"ORDER-PERMUTED  {name}  ({len(b)} fns)")
            for l in difflib.unified_diff(a, b, lineterm="", n=1):
                if l[:1] in "+-" and l[:3] not in ("---", "+++"):
                    print("   ", l)


def main():
    cmds = {"rank": cmd_rank, "where": cmd_where,
            "classify": cmd_classify, "order": cmd_order}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__)
        sys.exit(2)
    cmds[sys.argv[1]](tuple(sys.argv[2:]))


if __name__ == "__main__":
    main()
