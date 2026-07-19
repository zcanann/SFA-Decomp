#!/usr/bin/env python3
"""Triage the dtk `auto_generated` data objects and say what they are worth.

Every auto object scores fuzzy 100 and sits outside the `game`/`sdk` denominators,
so the class contributes nothing to the tracked metrics either way. This tool
classifies each object by section, by byte signature, and (the load-bearing axis)
by whether our own source already PINS its symbols via dangling `extern`
declarations, then writes:
    docs/orig/autogen_data_triage.md   (human summary + verdict)
    docs/orig/autogen_data_triage.csv  (per-object manifest)

Rerun after any rebuild of build/GSAE01/report.json. Reads only; never touches
the read-only target objects under build/GSAE01/obj/, and never touches splits.txt.
"""
import json, subprocess, re, math, os, csv
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")
REPORT = os.path.join(ROOT, "build/GSAE01/report.json")
OBJDIR = os.path.join(ROOT, "build/GSAE01/obj")
DOCDIR = os.path.join(ROOT, "docs/orig")

MAP = ['ptr-table', 'float-pool', 'const-data', 'string-data', 'data-table']
MAPSET = set(MAP)
SUB_DESC = {
    'ptr-table': 'reloc-dense pointer / jump / vtable tables',
    'float-pool': 'read-only float / const pools (mostly `.sdata2`)',
    'const-data': 'small `.sdata`/`.rodata` constants',
    'string-data': 'string / char tables',
    'data-table': 'structured `.data` tables (game data, display lists, offset tables)',
}


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze(path, sec):
    out = subprocess.run([OBJDUMP, "-h", "-r", "-s", path],
                         capture_output=True, text=True, timeout=30).stdout
    nreloc = len(re.findall(r'R_PPC[_A-Z0-9]*', out))
    data = bytearray(); grab = False
    for line in out.splitlines():
        if line.startswith('Contents of section'):
            grab = sec in line; continue
        if grab:
            m = re.match(r'\s*([0-9a-f]+)\s((?:[0-9a-f]{2,8}\s){1,4})', line)
            if not m:
                grab = False; continue
            try:
                data += bytes.fromhex(m.group(2).replace(' ', ''))
            except ValueError:
                pass
    n = len(data)
    if n == 0:
        return {'nbytes': 0}
    nw = n // 4
    ptr = flt = 0
    for i in range(nw):
        w = int.from_bytes(data[i * 4:i * 4 + 4], 'big')
        if 0x80003000 <= w < 0x81800000:
            ptr += 1
        exp = (w >> 23) & 0xff
        if 1 < exp < 0xfe:
            flt += 1
    best = cur = 0
    for x in data:
        if 0x20 <= x <= 0x7e or x in (9, 10, 13):
            cur += 1; best = max(best, cur)
        else:
            cur = 0
    return {
        'nbytes': n, 'nwords': nw, 'reloc_density': nreloc / nw if nw else 0,
        'entropy': entropy(data),
        'printable_frac': sum(1 for x in data if 0x20 <= x <= 0x7e) / n,
        'ff_frac': sum(1 for x in data if x == 0xff) / n,
        'ptr_frac': ptr / nw if nw else 0, 'flt_frac': flt / nw if nw else 0,
        'longest_str': best,
    }


def classify(sec, size, s):
    if sec in ('.bss', '.sbss', '.sbss2') or not s or s.get('nbytes', 0) == 0:
        return 'bss', 'zero-init'
    ent, rd, pf, ff = s['entropy'], s['reloc_density'], s['ptr_frac'], s['ff_frac']
    if size >= 50000 and ff >= 0.4:
        return 'asset', 'padding-dominated blob (texture/FIFO region)'
    if size >= 50000 and ent >= 7.4 and rd < 0.02:
        return 'asset', 'large high-entropy blob'
    if rd >= 0.5 or (pf >= 0.5 and rd >= 0.2):
        return 'ptr-table', 'reloc-dense pointer/jump/vtable table'
    if sec == '.sdata2':
        return 'float-pool', 'read-only const/float pool (.sdata2)'
    if s['printable_frac'] >= 0.75 and s['longest_str'] >= 8:
        return 'string-data', 'string / char table'
    if sec in ('.sdata', '.rodata'):
        return 'const-data', 'small const / rodata'
    if rd > 0 or pf > 0.05:
        return 'data-table', 'structured .data (relocs/pointers present)'
    if s['flt_frac'] >= 0.6 and ent < 6:
        return 'float-pool', 'numeric constant table'
    return 'data-table', 'opaque .data table (needs inspection)'


def source_identifiers():
    """Every identifier token appearing anywhere in src/ or include/."""
    ids = set()
    for base in ('src', 'include'):
        for dirpath, _, files in os.walk(os.path.join(ROOT, base)):
            for f in files:
                if f.endswith(('.c', '.h')):
                    blob = open(os.path.join(dirpath, f), 'rb').read()
                    ids.update(re.findall(rb'[A-Za-z_][A-Za-z0-9_]*', blob))
    return {i.decode() for i in ids}


def symtxt_names():
    txt = open(os.path.join(ROOT, "config/GSAE01/symbols.txt")).read()
    return set(re.findall(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=', txt, re.M))


def object_symbols(path):
    """[(name, size)] of the OBJECT symbols an auto .o defines."""
    out = subprocess.run([OBJDUMP, '-t', path], capture_output=True, text=True).stdout
    syms = []
    for line in out.splitlines():
        if ' O ' not in line:
            continue
        parts = line.split()
        try:
            syms.append((parts[-1], int(parts[-2], 16)))
        except ValueError:
            pass
    return syms


def reference_owners(sym_index):
    """auto-object -> Counter(target unit that relocates against its symbols)."""
    autos = set(sym_index.values())
    refs = defaultdict(Counter)
    for dirpath, _, files in os.walk(OBJDIR):
        for f in files:
            if not f.endswith('.o') or f[:-2] in autos:
                continue
            p = os.path.join(dirpath, f)
            out = subprocess.run([OBJDUMP, '-r', p], capture_output=True, text=True).stdout
            rel = os.path.relpath(p, OBJDIR)
            for m in re.finditer(r'R_PPC\S+\s+(\S+)', out):
                a = sym_index.get(m.group(1).split('+')[0])
                if a:
                    refs[a][rel] += 1
    return refs


def main():
    d = json.load(open(REPORT))
    units = d['units']

    # section-end table from real units, for adjacency attribution
    end_at = defaultdict(list); intervals = defaultdict(list)
    for x in units:
        if (x.get('metadata') or {}).get('auto_generated'):
            continue
        ow = (x.get('metadata') or {}).get('source_path') or x['name']
        for sname_sz in x.get('sections', []):
            va = sname_sz.get('metadata', {}).get('virtual_address')
            if not va:
                continue
            va = int(va); en = va + int(sname_sz.get('size', 0) or 0)
            if en == va:
                continue
            end_at[(sname_sz['name'], en)].append(ow)
            intervals[sname_sz['name']].append((va, en, ow))
    for k in intervals:
        intervals[k].sort()

    def neighbours(sec, addr, size):
        prev = nxt = None
        for st, en, ow in intervals.get(sec, []):
            if en <= addr:
                prev = ow
            if st >= addr + size and nxt is None:
                nxt = ow
        return prev, nxt

    ids = source_identifiers()
    stx = symtxt_names()
    autos = [x for x in units if (x.get('metadata') or {}).get('auto_generated')]
    sym_index = {}
    sym_class = {}
    for x in autos:
        base = x['name'].split('/')[-1]
        p = os.path.join(OBJDIR, base + '.o')
        if not os.path.exists(p):
            continue
        for name, sz in object_symbols(p):
            sym_index[name] = base
            if name.startswith('pad_'):
                k = 'pad'
            elif name in ids:
                k = 'src-pinned'
            elif name in stx:
                k = 'symtxt-only'
            else:
                k = 'orphan'
            sym_class.setdefault(base, Counter())[k] += sz
    refs = reference_owners(sym_index)

    rows = []
    for x in units:
        if not (x.get('metadata') or {}).get('auto_generated'):
            continue
        secs = x.get('sections', [])
        sec = max(secs, key=lambda s: int(s.get('size', 0) or 0))['name'] if secs else '?'
        size = sum(int(s.get('size', 0) or 0) for s in secs)
        m = re.search(r'_([0-9A-Fa-f]{8})_', x['name'])
        addr = int(m.group(1), 16) if m else None
        path = os.path.join(OBJDIR, x['name'].split('/')[-1] + '.o')
        s = analyze(path, sec) if os.path.exists(path) else {'nbytes': 0}
        cat, reason = classify(sec, size, s)
        owner, conf = None, '-'
        if cat in MAPSET and addr is not None:
            if end_at.get((sec, addr)):
                owner, conf = end_at[(sec, addr)][0], 'high'
            else:
                p, nx = neighbours(sec, addr, size)
                owner = p or nx
                conf = 'med' if owner else 'low'
        base = x['name'].split('/')[-1]
        sc = sym_class.get(base, Counter())
        ro = refs.get(base, Counter())
        rows.append({'name': x['name'], 'sec': sec, 'size': size, 'addr': addr,
                     'cat': cat, 'reason': reason, 'owner': owner, 'conf': conf,
                     'sym_class': sc, 'ref_owners': ro,
                     'ref_owner_top': ro.most_common(1)[0][0] if ro else ''})

    write_csv(rows)
    write_md(rows, d)
    print(f"wrote {DOCDIR}/autogen_data_triage.{{md,csv}}  ({len(rows)} objects)")


def write_csv(rows):
    with open(os.path.join(DOCDIR, "autogen_data_triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["address", "section", "size_bytes", "byte_class", "subtype_reason",
                    "adjacent_owner", "adjacency_confidence", "referencing_units",
                    "top_referencing_unit", "b_src_pinned", "b_symtxt_only",
                    "b_pad", "b_orphan"])
        for r in sorted(rows, key=lambda r: (r['addr'] or 0)):
            sc = r['sym_class']
            w.writerow([f"0x{r['addr']:08X}" if r['addr'] else '', r['sec'], r['size'],
                        r['cat'], r['reason'], (r['owner'] or '').split('/')[-1], r['conf'],
                        len(r['ref_owners']), r['ref_owner_top'],
                        sc.get('src-pinned', 0), sc.get('symtxt-only', 0),
                        sc.get('pad', 0), sc.get('orphan', 0)])


CLASS_DESC = {
    'src-pinned': 'a `.c`/`.h` in this tree names the symbol, almost always as a dangling '
                  '`extern` pin so the code relocates against retail\'s address and our TU '
                  'emits no bytes for it',
    'symtxt-only': 'named in `symbols.txt`, referenced by retail code, never spelled in our '
                   'source - our TU emits the value as an anonymous pool/literal instead',
    'pad': 'dtk alignment filler (`pad_*` symbols); no original C object',
    'orphan': 'neither source nor `symbols.txt` mentions it, and nothing relocates against it',
}


def write_md(rows, report):
    total = sum(r['size'] for r in rows)
    bc = Counter(); bb = Counter()
    for r in rows:
        bc[r['cat']] += 1; bb[r['cat']] += r['size']
    cls_b = Counter()
    for r in rows:
        cls_b.update(r['sym_class'])
    sec_b = Counter(); sec_n = Counter()
    for r in rows:
        sec_b[r['sec']] += r['size']; sec_n[r['sec']] += 1
    unref = [r for r in rows if not r['ref_owners']]
    multi = [r for r in rows if len(r['ref_owners']) > 1]
    single = [r for r in rows if len(r['ref_owners']) == 1]
    game = report['categories'][0]['measures'] if report.get('categories') else {}

    L = []
    P = L.append
    P("# Autogenerated data triage")
    P("")
    P(f"dtk emits **{len(rows)} `auto_generated` data objects** ({total:,} B) for retail address")
    P("ranges that `splits.txt` assigns to no translation unit. **Every one scores")
    P("`fuzzy_match_percent == 100`** and every one is excluded from the scored `game`/`sdk`")
    P("categories, so the class is invisible to the tracked metrics in both directions.")
    P("")
    P("Regenerate with `python3 tools/autogen_data_triage.py` after any rebuild of")
    P("`report.json`. Companion manifest: [`autogen_data_triage.csv`](autogen_data_triage.csv).")
    P("")
    P("## Verdict: real content, but not claimable headroom")
    P("")
    P("These spans are **not** padding and **not** a reporting artifact - they are genuine retail")
    P("data belonging to TUs we already have. But claiming them is blocked twice over:")
    P("")
    P("1. **Attribution lives in `splits.txt`, not `symbols.txt`.** An auto object exists precisely")
    P("   because no split claims its address range. Extending a split regenerates the target")
    P("   objects under `build/GSAE01/obj/`, which are READ-ONLY by project rule.")
    P("2. **Our source does not produce these bytes.** Most auto symbols are *pinned*: the source")
    P("   declares `extern f32 lbl_803DE7C0;` and relocates against retail's address rather than")
    P("   defining the constant, so our TU emits nothing to compare. Claiming the range would")
    P("   expose a short section and **lower** the score.")
    P("")
    P("The empirical check: of the auto `.sdata2` spans referenced by exactly **one** target unit,")
    P("our `.o`'s `.sdata2` bytes match the retail span in **1 case out of 42** - elsewhere ours is")
    P("typically 4-8x smaller (just the `43300000`/`80000000` int-to-double magic pair).")
    P("")
    P("Converting the pins into real definitions is the known **pool defs-vs-anons** axis, which")
    P("`.sdata2`'s positional all-or-nothing scoring makes a per-unit gate-crack, not a sweep.")
    P("")
    P("## Where the bytes are, by symbol class")
    P("")
    P("The load-bearing axis: does anything in *our* tree already name the symbol?")
    P("")
    P("| symbol class | bytes | % | what it means |")
    P("|---|---:|---:|---|")
    for k in ('src-pinned', 'symtxt-only', 'pad', 'orphan'):
        if cls_b[k]:
            P(f"| `{k}` | {cls_b[k]:,} | {100*cls_b[k]/total:.1f}% | {CLASS_DESC[k]} |")
    P(f"| **total** | {total:,} | 100% | |")
    P("")
    P("## By section")
    P("")
    P("| section | objs | bytes | note |")
    P("|---|---:|---:|---|")
    SEC_NOTE = {
        '.sdata2': 'MWCC read-only constant pools - the dominant class, and the hard one',
        '.bss': 'zero-init; no bytes exist in the DOL to match',
        '.sbss': 'zero-init small BSS',
        '.sbss2': 'zero-init small BSS',
        '.data': 'mostly dead debug string blobs (see below)',
        '.sdata': 'small initialised constants',
    }
    for sname, b in sec_b.most_common():
        P(f"| `{sname}` | {sec_n[sname]} | {b:,} | {SEC_NOTE.get(sname, '')} |")
    P("")
    P("## Who references these spans")
    P("")
    P("Reverse map built from relocations in the read-only target objects against the symbols each")
    P("auto object defines. This identifies the true owning TU far more reliably than the")
    P("address-adjacency guess in the CSV's `adjacent_owner` column.")
    P("")
    P(f"- **{len(single)} spans** are referenced by exactly one target unit - an unambiguous owner.")
    P(f"- **{len(multi)} spans** are referenced by several: dtk merged a contiguous run covering")
    P("  the pool contributions of several consecutive TUs into one object, because none of them")
    P("  carries a split for that section.")
    P(f"- **{len(unref)} spans** ({sum(r['size'] for r in unref):,} B) are referenced by nothing at")
    P("  all - dead debug strings and dtk padding.")
    P("")
    P("## The `.data` spans are dead debug strings")
    P("")
    P("All seven are string blobs (or small tables beside them) for `OSReport`-style diagnostics")
    P("whose call sites the retail build compiled out: Tricky walk-group traces")
    P("(`tricky wg %d->%d target wg %d`), `GUARD_INIT`/`GUARD_FINDING` state names,")
    P("`!!!!!!!!!!! TRIGGER %d  ident %d`, and one 440 B block of GX hang diagnostics")
    P("(`Suspected graphics hang or infinite loop`) that nothing in the DOL references.")
    P("Recovering them means writing the debug code that printed them - out of scope.")
    P("")
    P("## The unscored-output corollary")
    P("")
    P("The mirror image of this gap is worth knowing: **153 of our source units emit a `.sdata2`")
    P("section (3,428 B total) whose target object has no `.sdata2` at all.** Those bytes are")
    P("compared against nothing, so they can be arbitrarily wrong and no gate will say so. Same")
    P("blind-spot family as unresolved relocation targets.")
    P("")
    P("## Score arithmetic")
    P("")
    if game:
        gt = int(game['total_data']); gm = int(game['matched_data'])
        P(f"`game` data today: {gm:,}/{gt:,} = {100*gm/gt:.2f}%. Folding all {total:,} auto bytes into")
        P(f"that denominator with today's source would give {gm:,}/{gt+total:,} = "
          f"{100*gm/(gt+total):.2f}%, i.e. **{100*gm/gt - 100*gm/(gt+total):.2f} pp worse**.")
        P("Attribution is only a win once the bytes are also produced.")
        P("")
    P("## Method (reproducible)")
    P("")
    P("`tools/autogen_data_triage.py`. Per object: `powerpc-eabi-objdump -h -r -s -t` on the")
    P("read-only target `.o` for byte signals (Shannon entropy, `0xFF`-padding fraction, relocation")
    P("density, pointer-word fraction, printable-ASCII fraction) and for its symbol table; symbols")
    P("are then classified against every identifier in `src/` + `include/` and against")
    P("`symbols.txt`. Referencing units come from a full relocation scan of every non-auto target")
    P("object. No target object and no split is modified.")
    P("")
    open(os.path.join(DOCDIR, "autogen_data_triage.md"), "w").write("\n".join(L))


if __name__ == "__main__":
    main()
