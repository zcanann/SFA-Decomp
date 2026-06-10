#!/usr/bin/env python3
"""Per-line bisector for codegen-sensitive deref conversions, v3.

Usage: deref_bisect.py <src-rel-c-file> <mode> <var> [var...]

Converts the whole file (line-1:1 rewrites + optional include line at
top). While the byte gate fails: map the first .text divergence to its
function, revert that fn's converted lines ONE AT A TIME (gate after
each). After the gate passes, try re-applying each reverted line
individually, keeping every re-application that stays byte-identical.
"""
import subprocess, sys, os, re, struct

ROOT = os.environ.get('DEREF_ROOT', os.getcwd())
BASE = os.environ.get('DEREF_BASELINE', '/tmp/deref_baseline_o')

def sh(*args, **kw):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, **kw)

def symbols(opath):
    r = sh('build/binutils/powerpc-eabi-objdump', '-t', opath)
    if r.returncode != 0:
        r = sh('objdump', '-t', opath)
    syms = []
    for ln in r.stdout.splitlines():
        m = re.match(r'^([0-9a-f]{8})\s+.*\s+\.text\s+([0-9a-f]{8})\s+(\S+)$', ln)
        if m:
            addr, size, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
            if size > 0:
                syms.append((addr, size, name))
    return sorted(syms)

def text_bytes(opath):
    d = open(opath, 'rb').read()
    e_shoff, = struct.unpack('>I', d[0x20:0x24])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('>HHH', d[0x2e:0x34])
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack('>IIIIII', d[off:off+24])
        secs.append((name, offset, size))
    sh_off, sh_size = secs[e_shstrndx][1], secs[e_shstrndx][2]
    shstr = d[sh_off:sh_off+sh_size]
    for name, offset, size in secs:
        nm = shstr[name:shstr.index(b'\0', name)].decode()
        if nm == '.text':
            return d[offset:offset+size]
    return b''

def first_diff_sym(base_o, cur_o):
    bt, ct = text_bytes(base_o), text_bytes(cur_o)
    n = min(len(bt), len(ct))
    pos = next((i for i in range(n) if bt[i] != ct[i]),
               n if len(bt) != len(ct) else None)
    if pos is None:
        return None
    for addr, size, name in symbols(base_o):
        if addr <= pos < addr + size:
            return name
    return '<unmapped@%d>' % pos

def fn_range(lines, name):
    pat = re.compile(r'^[A-Za-z_][\w \t\*]*\b%s\s*\(' % re.escape(name))
    for i, L in enumerate(lines):
        if not pat.match(L):
            continue
        j = i
        bad = False
        while j < len(lines) and '{' not in lines[j]:
            if ';' in lines[j]:
                bad = True
                break
            j += 1
        if bad or j >= len(lines):
            continue
        if ';' in lines[j].split('{')[0]:
            continue
        depth, k = 0, j
        while k < len(lines):
            depth += lines[k].count('{') - lines[k].count('}')
            if depth == 0 and k >= j:
                break
            k += 1
        return (i, k)
    return None

def main():
    argv = sys.argv[1:]
    fn_whitelist = None
    if '--fns' in argv:
        i = argv.index('--fns')
        fn_whitelist = set(argv[i+1].split(','))
        argv = argv[:i] + argv[i+2:]
    cfile, mode, varnames = argv[0], argv[1], argv[2:]
    rel_o = cfile[len('src/'):-2] + '.o'
    cur_o = os.path.join(ROOT, 'build/GSAE01/src', rel_o)
    base_o = os.path.join(BASE, rel_o)
    abspath = os.path.join(ROOT, cfile)

    orig = open(abspath, 'rb').read().decode('latin-1')
    if mode.startswith(('struct:', 'structu:')):
        kind, header, sname = mode.split(':')
        args = ['python3', 'tools/deref_convert_struct.py', cfile, header, sname]
        if kind == 'structu':
            args.append('--include-unk')
    elif mode.startswith('scaled:'):
        _, header, sname, esz = mode.split(':')
        args = ['python3', 'tools/deref_scaled_convert.py', cfile, header, sname, esz]
    elif mode == 'index':
        args = ['python3', 'tools/deref_index_convert.py', cfile]
    elif mode in ('addr', 'addrb'):
        args = ['python3', 'tools/addr_convert_gameobject.py', cfile]
        if mode == 'addrb':
            args.append('--bytecast-only')
    else:
        args = ['python3', 'tools/deref_convert_gameobject.py', cfile]
        if mode == 'bytecast':
            args.append('--bytecast-only')
    print(sh(*args + varnames).stdout.strip())
    conv = open(abspath, 'rb').read().decode('latin-1')
    if conv == orig:
        print('NOCHANGE')
        return
    if mode.startswith(('struct:', 'structu:', 'scaled:')):
        h = mode.split(':')[1]
        need_inc = h[len('include/'):] if h.startswith('include/') else None
    else:
        need_inc = 'main/game_object.h'
    if need_inc and need_inc not in conv:
        m = re.search(r'^#include "[^"]+"', conv, re.M)
        conv = conv[:m.start()] + '#include "%s"\n' % need_inc + conv[m.start():]

    olines = orig.split('\n')
    clines = conv.split('\n')
    d = len(clines) - len(olines)  # 1 if include added else 0
    # state vector: for each orig line i with a conversion, applied?
    conv_lines = [i for i in range(len(olines)) if clines[i + d] != olines[i]]
    applied = {i: True for i in conv_lines}
    print('%d converted lines' % len(conv_lines))

    # struct modes: only keep conversions inside fns where the var is
    # locally associated with this struct (decl, cast, or param) - merged
    # TUs rebind the same name to different records per function.
    if mode.startswith(('struct:', 'structu:')):
        sname_ = mode.split(':')[2]
        assoc_res = [re.compile(r'\(\s*%s\s*\*\s*\)\s*\(?\s*%s\b' % (sname_, re.escape(v)))
                     for v in varnames] + \
                    [re.compile(r'\b%s\s*\*\s*%s\s*[=;,)]' % (sname_, re.escape(v)))
                     for v in varnames] + \
                    [re.compile(r'\b%s\s*=[^;=]*(->extra\b|\+\s*0[xX][bB]8\s*\))' % re.escape(v))
                     for v in varnames
                     # ->extra provenance is only unambiguous when the file
                     # associates this var with no OTHER State struct
                     if not any(s != sname_ for v2 in varnames for s in
                                re.findall(r'\(\s*(\w+State)\s*\*\s*\)\s*\(?\s*%s\b' % re.escape(v2), orig) +
                                re.findall(r'\b(\w+State)\s*\*\s*%s\s*[=;,)]' % re.escape(v2), orig))]

    conv_all = list(conv_lines)

    def write_state():
        cur = list(clines)
        for i in conv_all:
            if not applied[i]:
                cur[i + d] = olines[i]
        open(abspath, 'w', encoding='latin-1', newline='').write('\n'.join(cur))

    def gate():
        write_state()
        g = sh('python3', 'tools/deref_o_gate.py', base_o, cur_o, '--rebuild', ROOT)
        if 'errored' in g.stdout:
            return 'ERR'
        return g.returncode == 0

    def fn_of(line):
        for name, s, e in all_ranges:
            if s <= line <= e:
                return name
        return None

    all_ranges = []
    defre = re.compile(r'^[A-Za-z_][\w \t\*]*?\b(\w+)\s*\(')
    i = 0
    while i < len(olines):
        m = defre.match(olines[i])
        if m and not olines[i].lstrip().startswith(('typedef', '#', 'extern')):
            r = fn_range(olines[i:], m.group(1))
            if r is not None and r[0] == 0:
                all_ranges.append((m.group(1), i, i + r[1]))
                i = i + r[1] + 1
                continue
        i += 1

    if mode.startswith(('struct:', 'structu:')):
        dropped = 0
        fn_text = {name: '\n'.join(olines[s:e+1]) for name, s, e in all_ranges}
        for i in conv_lines:
            fn = fn_of(i)
            if fn_whitelist is not None:
                ok = fn in fn_whitelist
            else:
                ok = any(r.search(fn_text.get(fn, '')) for r in assoc_res)
            if not ok:
                applied[i] = False
                dropped += 1
        if dropped:
            print('%d lines dropped (fn lacks %s association)' % (dropped, sname_))
        conv_lines = [i for i in conv_lines if applied[i]]
        if not conv_lines:
            print('NOCHANGE after assoc filter')
            open(abspath, 'w', encoding='latin-1', newline='').write(orig)
            return

    # phase 1: greedy revert until gate passes
    for round_ in range(len(conv_lines) + 5):
        res = gate()
        if res == 'ERR':
            print('COMPILE-FAIL; reverting file')
            open(abspath, 'w', encoding='latin-1', newline='').write(orig)
            sh('ninja', os.path.relpath(cur_o, ROOT))
            return
        if res:
            break
        culprit = first_diff_sym(base_o, cur_o)
        cand = None
        if culprit and not culprit.startswith('<'):
            rng = fn_range(olines, culprit)
            if rng:
                cand = [i for i in conv_lines if applied[i] and rng[0] <= i <= rng[1]]
        if not cand:
            cand = [i for i in conv_lines if applied[i]]
        if not cand:
            print('nothing left to revert; reverting file')
            open(abspath, 'w', encoding='latin-1', newline='').write(orig)
            sh('ninja', os.path.relpath(cur_o, ROOT))
            return
        applied[cand[0]] = False
        print('revert line %d (%s)' % (cand[0] + 1, fn_of(cand[0])), flush=True)
    else:
        print('TOO MANY ROUNDS; reverting file')
        open(abspath, 'w', encoding='latin-1', newline='').write(orig)
        sh('ninja', os.path.relpath(cur_o, ROOT))
        return

    # phase 2: try re-applying reverted lines one at a time
    for i in [i for i in conv_lines if not applied[i]]:
        applied[i] = True
        res = gate()
        if res is not True:
            applied[i] = False
        else:
            print('re-applied line %d' % (i + 1), flush=True)
    write_state()
    final = gate()
    held = [i + 1 for i in conv_lines if not applied[i]]
    kept = sum(1 for i in conv_lines if applied[i])
    if final is True:
        print('PASS kept %d/%d lines; held-raw lines: %s (fns: %s)'
              % (kept, len(conv_lines), held,
                 sorted({fn_of(i - 1) for i in held})))
    else:
        print('FINAL GATE FAIL?! reverting file')
        open(abspath, 'w', encoding='latin-1', newline='').write(orig)
        sh('ninja', os.path.relpath(cur_o, ROOT))

if __name__ == '__main__':
    main()
