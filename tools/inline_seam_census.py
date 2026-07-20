#!/usr/bin/env python3
"""Inline-seam census: per-symbol bl-callee multiset + size, retail vs ours.

Answers "where does retail have an inlining boundary we lack (or vice versa)?"
by comparing, for every symbol present in both the retail and the source object,
the multiset of `bl` callee names and the symbol size.

  class A  retail calls X, we do not      -> we inlined X, retail did not
  class B  we call X, retail does not     -> retail inlined X, we did not
  class C  symbol only in the retail obj
  class D  symbol only in our obj         -> the spurious-unpaired-function vein

Caveats established in wave 89 / L167:
  * `_savegpr_N`/`_restgpr_N` differences are REGISTER-COUNT artifacts, not
    seams. They dominate class A and must be discounted.
  * build/GSAE01/src carries ~130 STALE ORPHANED objects that build.ninja no
    longer references. Pass --live to restrict to objects the build actually
    produces; without it every census over this tree is inflated (the
    unfolded-branch family read as 27 functions orphan-inclusive vs 11 live).
"""
import os, sys, argparse, collections
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

OBJ_ROOT = 'build/GSAE01/obj'
SRC_ROOT = 'build/GSAE01/src'


def scan(path):
    """-> {func: (size, Counter(callee_names))}"""
    out = {}
    with open(path, 'rb') as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name('.text')
        if text is None:
            return out
        secs = list(elf.iter_sections())
        text_idx = secs.index(text)
        data = text.data()

        symtab = None
        for sec in secs:
            if isinstance(sec, SymbolTableSection):
                symtab = sec
                break
        symnames = [s.name for s in symtab.iter_symbols()]

        reloc_at = {}
        for sec in secs:
            if isinstance(sec, RelocationSection) and sec.header['sh_info'] == text_idx:
                for r in sec.iter_relocations():
                    reloc_at[r['r_offset']] = symnames[r['r_info_sym']]

        funcs = []
        for sym in symtab.iter_symbols():
            if sym['st_shndx'] == text_idx and sym['st_info']['type'] == 'STT_FUNC' and sym['st_size']:
                funcs.append((sym['st_value'], sym['st_size'], sym.name))

        for start, size, name in funcs:
            body = data[start:start + size]
            callees = collections.Counter()
            for i in range(len(body) // 4):
                w = int.from_bytes(body[i * 4:i * 4 + 4], 'big')
                if (w >> 26) == 18 and (w & 1):  # bl
                    off = start + i * 4
                    callees[reloc_at.get(off, '<local>')] += 1
            out[name] = (size, callees)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--unit')
    ap.add_argument('--min-delta', type=int, default=1)
    ap.add_argument('--live', action='store_true',
                    help='restrict to objects referenced by build.ninja '
                         '(excludes stale orphaned .o files)')
    args = ap.parse_args()

    units = []
    for r, _, fs in os.walk(SRC_ROOT):
        for f in fs:
            if not f.endswith('.o'):
                continue
            rel = os.path.relpath(os.path.join(r, f), SRC_ROOT)
            if os.path.exists(os.path.join(OBJ_ROOT, rel)):
                units.append(rel)
    units.sort()
    if args.live:
        import re
        bn = open('build.ninja').read()
        keep = set(re.findall(r'build/GSAE01/src/([^\s:]+\.o)', bn))
        units = [u for u in units if u in keep]
    if args.unit:
        units = [u for u in units if args.unit in u]

    rows = []
    only_retail_sym = []
    only_ours_sym = []
    for rel in units:
        try:
            R = scan(os.path.join(OBJ_ROOT, rel))
            O = scan(os.path.join(SRC_ROOT, rel))
        except Exception as e:
            print(f'ERR {rel}: {e}', file=sys.stderr)
            continue
        for n in sorted(set(R) - set(O)):
            only_retail_sym.append((rel, n, R[n][0]))
        for n in sorted(set(O) - set(R)):
            only_ours_sym.append((rel, n, O[n][0]))
        for n in sorted(set(R) & set(O)):
            rs, rc = R[n]
            os_, oc = O[n]
            # callee multiset difference
            missing = rc - oc   # retail calls it, we don't -> WE INLINED (retail has seam)
            extra = oc - rc     # we call it, retail doesn't -> RETAIL INLINED
            if missing or extra:
                rows.append((rel, n, rs, os_, missing, extra))

    print(f'=== units compared: {len(units)} ===')
    print(f'\n### A. RETAIL HAS A SEAM WE LACK (retail bl, we inlined) ###')
    a = [r for r in rows if r[4]]
    for rel, n, rs, o, miss, extra in sorted(a, key=lambda r: -sum(r[4].values())):
        print(f'  {rel:46s} {n:40s} sz r{rs} o{o}  MISSING_BL {dict(miss)}' + (f'  EXTRA {dict(extra)}' if extra else ''))
    print(f'  [{len(a)}]')
    print(f'\n### B. RETAIL INLINED, WE CALL (we have a seam retail lacks) ###')
    b = [r for r in rows if r[5] and not r[4]]
    for rel, n, rs, o, miss, extra in sorted(b, key=lambda r: -sum(r[5].values())):
        print(f'  {rel:46s} {n:40s} sz r{rs} o{o}  EXTRA_BL {dict(extra)}')
    print(f'  [{len(b)}]')
    print(f'\n### C. symbol only in RETAIL obj [{len(only_retail_sym)}] ###')
    for rel, n, s in only_retail_sym[:60]:
        print(f'  {rel:46s} {n:40s} {s}')
    print(f'\n### D. symbol only in OUR obj [{len(only_ours_sym)}] ###')
    for rel, n, s in only_ours_sym[:60]:
        print(f'  {rel:46s} {n:40s} {s}')


if __name__ == '__main__':
    main()
