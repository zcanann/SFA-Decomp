#!/usr/bin/env python3
"""Triage the dtk `auto_generated` data objects: asset vs BSS vs mappable-backlog.

All 245 auto objects already byte-match (fuzzy 100) but sit outside the scored
game/sdk categories. This classifies every one and attributes the mappable ones
to a likely owning source unit by section-end adjacency, then writes:
    docs/orig/autogen_data_triage.md   (human summary)
    docs/orig/autogen_data_triage.csv  (per-object manifest)

Rerun after any rebuild of build/GSAE01/report.json. Reads only; never touches
the read-only target objects under build/GSAE01/obj/.
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
        rows.append({'name': x['name'], 'sec': sec, 'size': size, 'addr': addr,
                     'cat': cat, 'reason': reason, 'owner': owner, 'conf': conf})

    write_csv(rows)
    write_md(rows, int(d['measures']['total_data']))
    print(f"wrote {DOCDIR}/autogen_data_triage.{{md,csv}}  ({len(rows)} objects)")


def write_csv(rows):
    with open(os.path.join(DOCDIR, "autogen_data_triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["address", "section", "size_bytes", "class", "subtype_reason",
                    "likely_owner", "owner_confidence"])
        for r in sorted(rows, key=lambda r: (r['addr'] or 0)):
            cls = r['cat'] if r['cat'] in ('asset', 'bss') else r['cat']
            w.writerow([f"0x{r['addr']:08X}" if r['addr'] else '', r['sec'], r['size'],
                        cls, r['reason'], (r['owner'] or '').split('/')[-1], r['conf']])


def write_md(rows, dol_total):
    bc = Counter(); bb = Counter()
    for r in rows:
        bc[r['cat']] += 1; bb[r['cat']] += r['size']
    total = sum(bb.values())
    map_b = sum(bb[c] for c in MAP); map_n = sum(bc[c] for c in MAP)
    hi_b = sum(r['size'] for r in rows if r['cat'] in MAPSET and r['conf'] == 'high')
    hi_n = sum(1 for r in rows if r['cat'] in MAPSET and r['conf'] == 'high')
    ceiling = 100 * (dol_total - bb['asset']) / dol_total
    owner_agg = defaultdict(lambda: [0, 0])
    for r in rows:
        if r['cat'] in MAPSET:
            o = (r['owner'] or '??unattributed').split('/')[-1]
            owner_agg[o][0] += r['size']; owner_agg[o][1] += 1
    top = sorted(owner_agg.items(), key=lambda kv: -kv[1][0])

    L = []
    P = L.append
    P("# Autogenerated data triage")
    P("")
    P(f"dtk emits **{len(rows)} `auto_generated` data objects** ({total:,} B) that it could not attribute")
    P("to a source translation unit. All already byte-match (`fuzzy_match_percent == 100`): dtk")
    P("reconstructs every one from the user's disc at build time. But because they carry empty")
    P("`progress_categories`, they sit **outside** the scored `game`/`sdk` denominators, so they drag the")
    P("whole-DOL `matched_data_percent` down without representing real outstanding work.")
    P("")
    P("This file classifies **every** auto object so each excluded byte is named, and the genuinely")
    P("recoverable backlog is scoped and pre-attributed. Companion machine-readable manifest:")
    P("[`autogen_data_triage.csv`](autogen_data_triage.csv). Regenerate both with")
    P("`python3 tools/autogen_data_triage.py` after any rebuild of `report.json`.")
    P("")
    P("## Headline: it is one asset, not a wall")
    P("")
    P("| class | objs | bytes | % of auto | disposition |")
    P("|---|---:|---:|---:|---|")
    P(f"| **Boot-logo asset** | {bc['asset']} | {bb['asset']:,} | {100*bb['asset']/total:.0f}% | out-of-scope, documented — the **only** true asset |")
    P(f"| **BSS (zero-init)** | {bc['bss']} | {bb['bss']:,} | {100*bb['bss']/total:.0f}% | already matches; no committed bytes; trivial to attribute |")
    P(f"| **Mappable data** | {map_n} | {map_b:,} | {100*map_b/total:.0f}% | **in-scope backlog** — real structured data |")
    P(f"| **total** | {len(rows)} | {total:,} | 100% | |")
    P("")
    P(f"The only byte range that can **never** be committed is the boot logo ({bb['asset']:,} B). Everything")
    P("else is zero-init BSS or genuine structured data. Consequently the **ceiling on whole-DOL data")
    P(f"match is ~{ceiling:.0f}%** (`(total_data − boot_logo) / total_data`), and the in-scope")
    P("(`game`+`sdk`) data metric — which already excludes the asset by design — can reach **100%**.")
    P("")
    P("## The one asset")
    P("")
    P(f"A single {bb['asset']:,}-byte object, the boot / loading-screen texture set (Nintendo / Rareware /")
    P("Dolby logos, then `0xFF` padding, reused as the GX FIFO). Fully identified, extracted by dtk from")
    P("the disc, never committed — see [`embedded_assets.md`](embedded_assets.md). Its entropy is low")
    P("(~1.9) *because* it is 70% padding, so it is caught by padding-fraction, not entropy. **Done.**")
    P("")
    P(f"## BSS — {bb['bss']:,} B, {bc['bss']} objs")
    P("")
    P("`.bss`/`.sbss`/`.sbss2` zero-init ranges. Zero committed bytes and already matching; attributing")
    P("them (declaring the globals in the owning TU) is upside for the raw ratio with no data to write,")
    P("but low value — do last, or leave.")
    P("")
    P(f"## Mappable backlog — {map_b:,} B, {map_n} objs")
    P("")
    P("Genuine structured data dtk failed to attribute. By subtype:")
    P("")
    P("| subtype | objs | bytes | what it is |")
    P("|---|---:|---:|---|")
    for c in MAP:
        if bc[c]:
            P(f"| `{c}` | {bc[c]} | {bb[c]:,} | {SUB_DESC[c]} |")
    P("")
    P(f"**{hi_n} of {map_n} objects ({hi_b:,} B, {100*hi_b/map_b:.0f}% of mappable bytes) are")
    P("high-confidence attributed**: the blob's start address is *exactly* a known source unit's section")
    P("end, i.e. dtk split off data that continues straight out of that unit. Recovering these is \"append")
    P("this data to the TU that already owns the bytes just before it,\" not archaeology.")
    P("")
    P("### Mappable bytes by likely owning unit (top 25)")
    P("")
    P("| bytes | objs | likely owner |")
    P("|---:|---:|---|")
    for o, (b, n) in top[:25]:
        P(f"| {b:,} | {n} | `{o}` |")
    P("")
    P("Full per-object attribution is in the CSV. Confidence: `high` = exact section-end adjacency;")
    P("`med` = nearest real unit before/after; `low` = no neighbour found.")
    P("")
    P("## Recommended order of attack")
    P("")
    P("1. **`high`-confidence `data-table` / `ptr-table` blobs, largest first** — each appends to a named")
    P("   TU that already owns the preceding bytes; biggest raw-% gain per unit of effort.")
    P("2. **`float-pool` / `const-data`** — mechanically typed (`f32`/`f64`/const arrays), low risk.")
    P("3. **`string-data`** — small and easy, but watch SJIS / byte-wise editing rules.")
    P("4. **BSS** — optional cleanup; only global declarations to home.")
    P("5. **Boot logo** — no action; already done.")
    P("")
    P("## Method (reproducible)")
    P("")
    P("`tools/autogen_data_triage.py`. Per object: `powerpc-eabi-objdump -h -r -s` on the read-only target")
    P("`.o`, then classify by section + byte signals (Shannon entropy, `0xFF`-padding fraction, relocation")
    P("density, pointer-word fraction `0x80003000..0x81800000`, printable-ASCII fraction, longest string")
    P("run). Owner attribution matches each blob's start against the section-end table of all non-auto")
    P("units in `report.json`. No target object is modified.")
    P("")
    open(os.path.join(DOCDIR, "autogen_data_triage.md"), "w").write("\n".join(L))


if __name__ == "__main__":
    main()
