#!/usr/bin/env python3
"""Compare a unit's built CONSTANT-POOL CONTENT against the retail image.

The missing third leg beside order_check (function placement) and
section_size_check (section extents). Both of those, plus objdiff's fuzzy score,
are structurally blind to a pool whose SIZE is right and whose VALUES are wrong:

  * objdiff pairs .text functions by name and scores instruction content. An
    `lfs f1, -0x49f4(r2)` scores identical to the retail `lfs f1, -0x49e8(r2)`
    under mnemonic comparison of a matched function only if the displacement
    also matches -- but when the WRONG VALUE lands at the RIGHT SLOT the .text
    is byte-identical and the defect is entirely in .sdata2, which fuzzy never
    reads.
  * section_size_check compares sizes only. A same-size, wrong-content pool
    passes it.
  * main.dol's sha1 is blind while the unit is INCOMPLETE, because the link
    consumes the retail object. The defect appears the instant it is promoted.

cameramodeforcebehind was the worked example: our pool slot 0x803E1B0C held
0.25 where retail holds 0.0, and the .text referenced it at a different SDA2
displacement (b60c vs retail b618).

Ground truth is orig/GSAE01/sys/main.dol. For each unit that claims a data
range in config/GSAE01/splits.txt, this reads the same-named section out of our
built object and compares it word-for-word against the retail bytes at the
claimed address.

_SDA2_BASE_ = 0x803E6500, _SDA_BASE_ = 0x803E31E0 (displacements are printed
relative to whichever base covers the address, to line up with the .text).

usage: python3 tools/pool_content_check.py [unit-substring ...]
       --sections .sdata2,.sdata   sections to compare (default .sdata2)
       --all-sections              compare every rodata/data-class section
       --quiet                     one line per failing unit
exit status 1 if any scanned unit has a content mismatch.
"""
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, 'build/binutils/powerpc-eabi-objdump')
DOL = os.path.join(ROOT, 'orig/GSAE01/sys/main.dol')
SPLITS = os.path.join(ROOT, 'config/GSAE01/splits.txt')

SDA2_BASE = 0x803E6500
SDA_BASE = 0x803E31E0

DEFAULT_SECTIONS = ('.sdata2',)
ALL_SECTIONS = ('.rodata', '.data', '.sdata', '.sdata2')


class Dol(object):
    def __init__(self, path):
        blob = open(path, 'rb').read()
        offs = struct.unpack('>18I', blob[0x00:0x48])
        addrs = struct.unpack('>18I', blob[0x48:0x90])
        sizes = struct.unpack('>18I', blob[0x90:0xD8])
        self.blob = blob
        self.spans = [(addrs[i], sizes[i], offs[i])
                      for i in range(18) if sizes[i]]

    def read(self, addr, length):
        """Bytes at virtual address, or None if not fully mapped."""
        for a, sz, off in self.spans:
            if a <= addr and addr + length <= a + sz:
                start = off + (addr - a)
                return self.blob[start:start + length]
        return None


def parse_splits(path):
    """unit source path (e.g. main/foo.c) -> {section: (start, end)}"""
    units = {}
    cur = None
    for line in open(path):
        if not line.strip() or line.startswith('#'):
            continue
        if not line[0].isspace():
            name = line.strip()
            if name.endswith(':'):
                name = name[:-1]
            if name == 'Sections':
                cur = None
                continue
            cur = units.setdefault(name, {})
            continue
        if cur is None:
            continue
        m = re.match(r'\s*(\S+)\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)',
                     line)
        if m:
            cur[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    return units


def section_bytes(obj_path, section):
    """Raw contents of `section` in an object file, or None if absent."""
    r = subprocess.run([OBJDUMP, '-s', '-j', section, obj_path],
                       capture_output=True)
    if r.returncode != 0:
        return None
    data = bytearray()
    seen = False
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        if line.startswith('Contents of section '):
            seen = line.split()[3].rstrip(':') == section
            continue
        if not seen:
            continue
        m = re.match(r'\s*([0-9a-f]+)\s((?:[0-9a-f]{2,8}\s){1,4})\s', line)
        if not m:
            continue
        data += bytes.fromhex(m.group(2).replace(' ', ''))
    return bytes(data) if seen or data else None


def has_relocs(obj_path, section):
    r = subprocess.run([OBJDUMP, '-r', obj_path], capture_output=True)
    if r.returncode != 0:
        return False
    active = False
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        if line.startswith('RELOCATION RECORDS FOR ['):
            active = line.split('[')[1].split(']')[0] == section
            continue
        if active and re.match(r'^[0-9a-f]{8}\s', line):
            return True
    return False


def disp(addr):
    if SDA2_BASE - 0x8000 <= addr < SDA2_BASE + 0x8000:
        return 'r2%+d (%04x)' % (addr - SDA2_BASE,
                                 (addr - SDA2_BASE) & 0xFFFF)
    if SDA_BASE - 0x8000 <= addr < SDA_BASE + 0x8000:
        return 'r13%+d (%04x)' % (addr - SDA_BASE,
                                  (addr - SDA_BASE) & 0xFFFF)
    return '-'


def f32(word):
    return struct.unpack('>f', word)[0]


def shift_hint(ours, dol, base, span):
    """If our whole pool appears verbatim elsewhere nearby, say where.

    A pool that matches at a DIFFERENT address is a CLAIM/ORDER defect (the
    split hands the unit the wrong slice), not a wrong literal in the source.
    """
    if len(ours) < 8:
        return None
    for delta in range(-0x200, 0x201, 4):
        if delta == 0:
            continue
        blob = dol.read(base + delta, len(ours))
        if blob is not None and blob == ours:
            return delta
    return None


def compare(name, section, ours, claim, dol, quiet):
    """Return list of report lines (empty == clean)."""
    base, end = claim
    span = end - base
    lines = []
    n = len(ours)
    if n > span:
        lines.append('  [size] %s ours=0x%x claim=0x%x -- comparing the '
                     'claimed 0x%x only (section_size_check owns the rest)'
                     % (section, n, span, span))
        ours = ours[:span]
    retail = dol.read(base, len(ours))
    if retail is None:
        return ['  [skip] %s not mapped in the DOL at 0x%08X' % (section, base)]
    bad = []
    for off in range(0, len(ours) & ~3, 4):
        a, b = ours[off:off + 4], retail[off:off + 4]
        if a != b:
            bad.append((off, a, b))
    tail = len(ours) & 3
    if tail and ours[-tail:] != retail[-tail:]:
        bad.append((len(ours) - tail, ours[-tail:], retail[-tail:]))
    if not bad:
        return lines
    words = max(1, len(ours) // 4)
    kind = 'BAD'
    note = ''
    delta = shift_hint(ours, dol, base, span)
    if delta is not None:
        kind = 'SHIFT'
        note = '  -- our pool matches retail VERBATIM at %+d (0x%08X): the ' \
               'CLAIM is misplaced, not the values' % (delta, base + delta)
    else:
        full = dol.read(base, span) or retail
        ow = sorted(ours[i:i + 4] for i in range(0, len(ours) & ~3, 4))
        rw = sorted(full[i:i + 4] for i in range(0, len(full) & ~3, 4))
        pad = b'\x00\x00\x00\x00'
        rw_nopad = list(rw)
        if pad in rw_nopad:
            rw_nopad.remove(pad)
        if ow == rw:
            kind = 'PERM'
            note = '  -- same VALUES in a different ORDER: an emission-order ' \
                   '(first-use) artifact, NOT a wrong literal'
        elif ow == rw_nopad:
            kind = 'PERM'
            note = '  -- same VALUES in a different ORDER, plus one retail ' \
                   'zero word: the 4-byte ALIGNMENT PAD the reordering pushes ' \
                   'ahead of the 8-aligned int-to-float magic pair. Still an ' \
                   'emission-order artifact, NOT a wrong literal'
    lines.append('  [%s] %-8s %d/%d words differ  (0x%08X..0x%08X)%s'
                 % (kind, section, len(bad), words, base, base + len(ours),
                    note))
    if quiet or kind == 'SHIFT':
        return lines
    for off, a, b in bad:
        addr = base + off
        av = '%.9g' % f32(a) if len(a) == 4 else ''
        bv = '%.9g' % f32(b) if len(b) == 4 else ''
        lines.append('    +0x%03x  0x%08X  %-14s ours=%s (%s)  retail=%s (%s)'
                     % (off, addr, disp(addr), a.hex(), av, b.hex(), bv))
    return lines


def main():
    argv = sys.argv[1:]
    quiet = '--quiet' in argv
    sections = list(DEFAULT_SECTIONS)
    if '--all-sections' in argv:
        sections = list(ALL_SECTIONS)
    filters = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('--quiet', '--all-sections'):
            pass
        elif a == '--sections':
            i += 1
            sections = [s if s.startswith('.') else '.' + s
                        for s in argv[i].split(',')]
        elif a.startswith('--sections='):
            sections = [s if s.startswith('.') else '.' + s
                        for s in a.split('=', 1)[1].split(',')]
        else:
            filters.append(a)
        i += 1

    dol = Dol(DOL)
    splits = parse_splits(SPLITS)
    units = json.load(open(os.path.join(ROOT, 'objdiff.json')))['units']

    scanned = bad_units = 0
    bad_names = []
    for u in units:
        name = u.get('name', '')
        src = (u.get('metadata') or {}).get('source_path', '')
        if filters and not any(f in name or f in src for f in filters):
            continue
        ours_p = u.get('base_path')
        if not ours_p or not src:
            continue
        ours_p = os.path.join(ROOT, ours_p)
        if not os.path.exists(ours_p):
            continue
        key = src[4:] if src.startswith('src/') else src
        claims = splits.get(key)
        if not claims:
            continue
        scanned += 1
        report = []
        for section in sections:
            if section not in claims:
                continue
            data = section_bytes(ours_p, section)
            if not data:
                continue
            if has_relocs(ours_p, section):
                report.append('  [skip] %s carries relocations' % section)
                continue
            report += compare(name, section, data, claims[section], dol, quiet)
        if any(k in ln for ln in report for k in ('[BAD]', '[SHIFT]', '[PERM]')):
            bad_units += 1
            bad_names.append(name)
        if report:
            print('\n=== %s' % name)
            print('\n'.join(report))

    print('\nscanned=%d content-mismatch=%d  sections=%s'
          % (scanned, bad_units, ','.join(sections)))
    for n in bad_names:
        print('  MISMATCH %s' % n)
    return 1 if bad_units else 0


if __name__ == '__main__':
    sys.exit(main())
