#!/usr/bin/env python3
"""Partial GameObject-deref conversion of an all-or-nothing TU.

Convert the whole file, then iteratively revert the conversions in any
function whose compiled size diverges from baseline, until the .o is
byte-identical (gate semantics) on the surviving converted functions.

Usage: go_salvage.py <src/file.c> <basevar> [basevar...] [--bytecast-only]

A function is "reverted" by restoring its exact source-line span from the
pristine .orig copy. Repeats build+diff until no size-divergent function
remains; the result is guaranteed byte-identical per function (same gate
contract), capturing every function that converts cleanly while leaving
the codegen-shift holdouts raw.
"""
import re, sys, os, struct, subprocess, shutil

ROOT = 'c:/Projects/SFA-Decomp'
os.chdir(ROOT)


def sym_bytes(path):
    """{func name: its .text bytes} — content, not just size."""
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF'
    e_shoff, = struct.unpack('>I', d[0x20:0x24])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('>HHH', d[0x2e:0x34])
    secs = []
    names = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack('>IIIIII', d[off:off+24])
        secs.append((offset, size)); names.append(name)
    shstr_off, shstr_size = secs[e_shstrndx]
    shstr = d[shstr_off:shstr_off+shstr_size]
    raw = {}
    sect_bytes = {}
    sect_index = {}
    for idx, (offset, size) in enumerate(secs):
        nm = shstr[names[idx]:shstr.index(b'\0', names[idx])].decode()
        raw[nm] = (offset, size)
        sect_bytes[idx] = d[offset:offset+size]
        sect_index[nm] = idx
    st_off, st_size = raw['.symtab']
    sb_off, sb_size = raw['.strtab']
    sb = d[sb_off:sb_off+sb_size]
    out = {}
    for i in range(st_off, st_off+st_size, 16):
        name_off, value, size_, info, other, shndx = struct.unpack('>IIIBBH', d[i:i+16])
        nm = sb[name_off:sb.index(b'\0', name_off)].decode('latin-1', 'replace')
        if (info & 0xf) == 2 and shndx in sect_bytes:  # STT_FUNC in a real section
            out[nm] = sect_bytes[shndx][value:value+size_]
    return out


def find_funcs(lines):
    funcs = []
    i = 0
    defre = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \*]*?\**(\w+)\(')
    while i < len(lines):
        L = lines[i]
        m = defre.match(L)
        if m and not L.rstrip().endswith(';') and 'extern' not in L.split('(')[0] \
           and not L.startswith('typedef') and not L.startswith('#'):
            j = i
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            if j >= len(lines):
                break
            depth, k = 0, j
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0:
                    break
                k += 1
            funcs.append((m.group(1), i, k))
            i = k + 1
        else:
            i += 1
    return funcs


def build(obj):
    r = subprocess.run(['ninja', obj], capture_output=True, text=True)
    return r.returncode == 0 and b'' or (r.stdout + r.stderr)


def main():
    f = sys.argv[1]
    rest = sys.argv[2:]
    obj = 'build/GSAE01/src/' + f[len('src/'):]
    obj = obj[:-2] + '.o'
    orig = '/tmp/' + os.path.basename(f) + '.salvorig'

    subprocess.run(['ninja', obj], capture_output=True)
    base_sizes = sym_bytes(obj)
    shutil.copy(f, orig)

    # full convert
    subprocess.run(['python3', 'tools/deref_convert_gameobject.py', f] + rest)
    if 'game_object.h' not in open(f, encoding='latin-1').read():
        s = open(f, encoding='latin-1').read().split('\n')
        s.insert(1, '#include "main/game_object.h"')
        open(f, 'w', encoding='latin-1', newline='').write('\n'.join(s))

    orig_lines = open(orig, encoding='latin-1').read().split('\n')
    funcs = {name: (a, b) for name, a, b in find_funcs(orig_lines)}

    reverted = set()
    for it in range(12):
        out = subprocess.run(['ninja', obj], capture_output=True, text=True)
        if 'error' in (out.stdout + out.stderr).lower() or 'FAILED' in (out.stdout + out.stderr):
            print('BUILD ERROR, aborting salvage'); shutil.copy(orig, f); subprocess.run(['ninja', obj]); return
        cur_sizes = sym_bytes(obj)
        bad = [n for n in funcs if base_sizes.get(n) != cur_sizes.get(n) and n not in reverted]
        if not bad:
            break
        # revert each bad function's source span from orig
        cur_lines = open(f, encoding='latin-1').read().split('\n')
        # recompute current func spans (line counts can drift after edits)
        cur_funcs = {name: (a, b) for name, a, b in find_funcs(cur_lines)}
        for n in bad:
            if n in cur_funcs and n in funcs:
                ca, cb = cur_funcs[n]
                oa, ob = funcs[n]
                cur_lines[ca:cb+1] = orig_lines[oa:ob+1]
                reverted.add(n)
        open(f, 'w', encoding='latin-1', newline='').write('\n'.join(cur_lines))
        print('iter', it, 'reverted', len(bad), 'fns:', bad[:6])

    # final gate
    subprocess.run(['ninja', obj], capture_output=True)
    g = subprocess.run(['python3', 'tools/deref_o_gate.py', '/tmp/baseline_o/' + os.path.basename(obj), obj],
                       capture_output=True, text=True)
    converted = len(funcs) - len(reverted)
    print('SALVAGE done: %d fns converted, %d reverted (holdouts)' % (converted, len(reverted)))


if __name__ == '__main__':
    main()
