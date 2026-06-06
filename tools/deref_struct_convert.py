#!/usr/bin/env python3
"""Generic offset-deref -> struct member converter for SFA-Decomp deref cleanup.

Usage:
  deref_tool.py inventory <config.json>   # print offset/type inventory
  deref_tool.py header <config.json>      # emit struct header body to stdout
  deref_tool.py convert <config.json>     # convert file in place (from .orig)

Config JSON:
{
  "root": "/home/jack/code/sfa-deref-dll-a",
  "file": "src/main/dll/andross.c",
  "orig": "/tmp/andross_orig.c",          # pristine copy
  "struct": "AndrossState",
  "size": "0xEC",
  "mapping": "/tmp/andross_map.json",     # offset -> [member, type] (written by `header`)
  "local_inits": ["\\\\*\\\\(int \\\\*\\\\)\\\\(obj \\\\+ 0xb8\\\\)"],  # RHS patterns marking a local as record (byte base)
  "vars": {                                 # extra per-fn record vars: fn -> {var: es}
     "fn_8023A87C": {"p2": 1}
  },
  "global_vars": {"piVar14": 4, "state": 1, "iVar12": 1},  # name -> element size, auto if init matches
  "skip": [],                                # fn names left raw
  "varb": []                                 # fn names forced to inline-cast strategy
}
Strategy: locals whose init matches local_inits[] AND all uses are handled get
retyped; everything else converts via inline ((T *)var)-> casts. Offsets used
as bare addresses in a fn are excluded fn-wide (address-CSE).
"""
import re, json, sys, os, collections

TYPES = r'(?:u8|s8|u16|s16|u32|s32|int|f32|f64|char|short|void|uint|ushort|byte|float|undefined4|undefined2|undefined1|undefined)'
W = {'u8':1,'s8':1,'char':1,'u16':2,'s16':2,'short':2,'int':4,'u32':4,'s32':4,'f32':4,'f64':8}
def width(t): return 4 if t.endswith('*') else W.get(t,4)
def norm(t): return ' '.join(t.split())

def load(cfgpath):
    cfg = json.load(open(cfgpath))
    src = open(cfg['orig'],'rb').read().decode('latin-1')
    return cfg, src

def find_funcs(lines):
    funcs = []; i = 0
    defre = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \*]*?\**(\w+)\(([^)]*)\)')
    while i < len(lines):
        L = lines[i]
        m = defre.match(L)
        if m and not L.rstrip().endswith(';') and 'extern' not in L.split('(')[0] \
           and not L.startswith('typedef') and not L.startswith('#'):
            if '{' in L and L.count('{') == L.count('}'):
                funcs.append((m.group(1), i, i)); i += 1; continue
            j = i
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            if j >= len(lines): break
            depth, k = 0, j
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0: break
                k += 1
            funcs.append((m.group(1), i, k)); i = k + 1
        else:
            i += 1
    return funcs

def fn_vars(cfg, name, body):
    """record vars active in this fn: {var: (es, is_local_retypable_init)}"""
    out = {}
    # params listed in config param_names, matched against the def line
    defline = body.split('\n')[0]
    m = re.match(r'[^(]*\(([^)]*)', defline)
    if m:
        ES = {'int':1,'u8 *':1,'char *':1,'void *':1,'uchar *':1,'byte *':1,
              'short *':2,'s16 *':2,'u16 *':2,'ushort *':2,
              'int *':4,'uint *':4,'s32 *':4,'u32 *':4}
        for p in m.group(1).split(','):
            p = ' '.join(p.strip().split())
            if p.startswith('register '):
                p = p[9:]
            pm = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*(?: \*+)?)\s*(\w+)$', p.replace('*', ' * ').replace('  ',' ').replace(' * ',' *'))
            if pm and pm.group(2) in cfg.get('param_names', []) and pm.group(1) in ES:
                out[pm.group(2)] = (ES[pm.group(1)], False)
    # locals: `[int [*]]X = <init>;` -- init pattern determines element size
    for ent in cfg.get('local_inits', []):
        pat, es = ent['pat'], ent['es']
        for m in re.finditer(r'\b(\w+) = (' + pat + r');', body):
            out[m.group(1)] = (es, True)
    for var, es in cfg.get('global_vars', {}).items():
        if var not in out and re.search(r'\b'+var+r'\b', body):
            # only if it's a record here: init match or listed per-fn
            pass
    for var, es in cfg.get('vars', {}).get(name, {}).items():
        out[var] = (es, False)
    af = cfg.get('auto_fingerprint')
    if af:
        mapping = {int(k,16): tuple(v) for k,v in json.load(open(cfg['mapping'])).items()}
        deny = set(af.get('deny', ['obj','playerObj','setup','model']))
        cand = set(re.findall(r'\((\w+) \+ 0x[0-9a-fA-F]+\)', body)) - deny - set(out)
        for var in cand:
            hits = set()
            for rex, mul, kind in patterns(var, 1):
                if kind != 'deref': continue
                for m in rex.finditer(body):
                    t, off = norm(m.group(1)), int(m.group(2),0)*mul
                    t = {'short':'s16','s32':'int','float':'f32','uint':'u32','ushort':'u16','byte':'u8','undefined4':'u32','undefined2':'u16','undefined1':'u8','undefined':'u8'}.get(t, t)
                    if off in mapping and mapping[off][1] == t:
                        hits.add(off)
            if len(hits) >= af.get('min_hits', 3):
                out[var] = (1, False)
    return out

def patterns(var, es):
    """list of (regex, kind) yielding (type, byte_off). kind: deref/index/deref0"""
    v = re.escape(var)
    pats = [
        (re.compile(r'\*\(\s*('+TYPES+r'(?:\s*\*)*?)\s*\*\s*\)\(\(char \*\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)\)'), 1, 'deref'),
        (re.compile(r'\*\(\s*('+TYPES+r'(?:\s*\*)*?)\s*\*\s*\)\(\(int\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)\)'), 1, 'deref'),
        (re.compile(r'\*\(\s*('+TYPES+r'(?:\s*\*)*?)\s*\*\s*\)\('+v+r' \+ (0x[0-9a-fA-F]+|\d+)\)'), es, 'deref'),
    ]
    if es == 4:
        pats.append((re.compile(r'\b'+v+r'\[(0x[0-9a-fA-F]+|\d+)\]'), 4, 'index'))
    return pats

def inventory(cfg, src):
    lines = src.split('\n')
    inv = collections.defaultdict(collections.Counter)
    for name, s, e in find_funcs(lines):
        body = '\n'.join(lines[s:e+1])
        for var, (es, _) in fn_vars(cfg, name, body).items():
            for rex, mul, kind in patterns(var, es):
                for m in rex.finditer(body):
                    if kind == 'index':
                        inv[int(m.group(1),0)*4]['int'] += 1
                    else:
                        inv[int(m.group(2),0)*mul][norm(m.group(1))] += 1
            if es == 4 and re.search(r'\*'+re.escape(var)+r'\b(?!\[)', body):
                inv[0]['int'] += len(re.findall(r'(?<![\w\)])\*'+re.escape(var)+r'\b(?!\[)', body))
    return inv

def choose_fields(cfg, inv):
    if cfg['size'] == 'auto':
        mx = max(inv) if inv else 0
        cfg['size'] = hex((mx + 8) & ~3)
    size = int(cfg['size'], 0)
    fields = {}
    for off in sorted(inv):
        if off >= size: continue
        c = inv[off]
        # merge alias counts onto canonical types before majority vote
        AL = {'short':'s16','s32':'int','float':'f32','uint':'u32','ushort':'u16',
              'byte':'u8','undefined4':'u32','undefined2':'u16','undefined1':'u8',
              'undefined':'u8','char':'u8'}
        cc = collections.Counter()
        for k,v in c.items():
            cc[AL.get(k,k)] += v
        t = max(cc.items(), key=lambda kv:(kv[1], kv[0]=='int'))[0]
        fields[off] = t
    # demote overlaps: prefer the later (finer) field, shrink earlier to u8 if evidence, else drop
    offs = sorted(fields)
    for i, off in enumerate(list(offs)):
        if off not in fields: continue
        t = fields[off]
        nxt = next((o for o in offs if o > off and o in fields), None)
        if nxt is not None and off + width(t) > nxt:
            if inv[off].get('u8'): fields[off] = 'u8'
            elif inv[off].get('s16') and off+2 <= nxt: fields[off] = 's16'
            elif inv[off].get('u16') and off+2 <= nxt: fields[off] = 'u16'
            else: del fields[off]
    return fields

def emit_header(cfg, fields):
    if cfg['size'] == 'auto':
        mx = max(fields) if fields else 0
        cfg['size'] = hex((mx + 8) & ~3)
    size = int(cfg['size'], 0)
    lines, pos = [], 0
    for off in sorted(fields):
        t = fields[off]
        if off > pos:
            lines.append('    u8 unk%X[0x%X - 0x%X];' % (pos, off, pos))
        name = 'unk%X' % off
        lines.append(('    %s%s;' if t.endswith('*') else '    %s %s;') % (t if t.endswith('*') else t+' ', name) if False else
                     ('    %s%s;' % (t, name) if t.endswith('*') else '    %s %s;' % (t, name)))
        pos = off + width(t)
    if pos < size:
        lines.append('    u8 unk%X[0x%X - 0x%X];' % (pos, size, pos))
    mapping = {('0x%x' % off): ['unk%X' % off, fields[off]] for off in fields}
    json.dump(mapping, open(cfg['mapping'],'w'), indent=0)
    return '\n'.join(lines)

def convert(cfg, src):
    lines = src.split('\n')
    mapping = {int(k,16): tuple(v) for k,v in json.load(open(cfg['mapping'])).items()}
    skip = set(cfg.get('skip', []))
    varb = set(cfg.get('varb', []))
    T = cfg['struct']
    stats = collections.Counter()
    out_lines = list(lines)
    for name, s, e in find_funcs(lines):
        if name in skip: continue
        body = '\n'.join(lines[s:e+1])
        vars_here = fn_vars(cfg, name, body)
        if not vars_here: continue
        total = 0
        for var, (es, retypable) in vars_here.items():
            v = re.escape(var)
            # collect all base-offset usages for address-CSE exclusion
            alladdr = []
            for rex in (r'\(char \*\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)', r'\(int\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)',
                        r'(?<![\w\)])'+v+r' \+ (0x[0-9a-fA-F]+|\d+)'):
                for m in re.finditer(rex, body):
                    mul = es if '(' not in m.re.pattern[:8] else 1
            # simpler: recompute below
            addr_off = []
            for m in re.finditer(r'\(char \*\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)', body):
                addr_off.append(int(m.group(1),0))
            for m in re.finditer(r'\(int\)'+v+r' \+ (0x[0-9a-fA-F]+|\d+)', body):
                addr_off.append(int(m.group(1),0))
            for m in re.finditer(r'(?<![\w\*\)])'+v+r' \+ (0x[0-9a-fA-F]+|\d+)', body):
                addr_off.append(int(m.group(1),0)*es)
            deref_off = []
            for rex, mul, kind in patterns(var, es):
                for m in rex.finditer(body):
                    if kind == 'deref':
                        deref_off.append(int(m.group(2),0)*mul)
            da = list(deref_off); excl = set()
            for o in addr_off:
                if o in da: da.remove(o)
                else: excl.add(o)
            spell = '((%s *)%s)->' % (T, var)
            cnt = [0]
            def mk(mul, kind):
                def repl(m):
                    if kind == 'index':
                        off = int(m.group(1),0)*4; t = 'int'
                    else:
                        t, off = norm(m.group(1)), int(m.group(2),0)*mul
                        t = {'short':'s16','s32':'int','float':'f32','uint':'u32','ushort':'u16','byte':'u8','undefined4':'u32','undefined2':'u16','undefined1':'u8','undefined':'u8'}.get(t, t)
                    if off in excl or off not in mapping or mapping[off][1] != t:
                        return m.group(0)
                    cnt[0] += 1
                    return spell + mapping[off][0]
                return repl
            nb = body
            for rex, mul, kind in patterns(var, es):
                nb = rex.sub(mk(mul, kind), nb)
            if es == 4 and 0 in mapping and mapping[0][1] == 'int' and 0 not in excl:
                declre = re.compile(r'^\s*(?:int|u8|s8|u16|s16|u32|s32|f32|char|short|void)\s*\*')
                d0 = re.compile(r'(?<![\w\)])\*'+v+r'\b(?!\[)')
                pieces = []
                for ln in nb.split('\n'):
                    if not declre.match(ln):
                        cnt[0] += len(d0.findall(ln))
                        ln = d0.sub(spell + mapping[0][0], ln)
                    pieces.append(ln)
                nb = '\n'.join(pieces)
            if cnt[0]: total += cnt[0]
            body = nb
        if total:
            out_lines[s:e+1] = body.split('\n')
            stats['fns'] += 1; stats['derefs'] += total
    res = '\n'.join(out_lines)
    inc = cfg.get('include_line')
    if inc and inc['add'] not in res:
        res = res.replace(inc['after'], inc['after'] + '\n' + inc['add'], 1)
    open(os.path.join(cfg['root'], cfg['file']),'wb').write(res.encode('latin-1'))
    print(dict(stats))

if __name__ == '__main__':
    cmd, cfgpath = sys.argv[1], sys.argv[2]
    cfg, src = load(cfgpath)
    if cmd == 'inventory':
        inv = inventory(cfg, src)
        for off in sorted(inv):
            print(hex(off), dict(inv[off]))
    elif cmd == 'header':
        inv = inventory(cfg, src)
        print(emit_header(cfg, choose_fields(cfg, inv)))
    elif cmd == 'convert':
        convert(cfg, src)
