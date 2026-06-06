#!/usr/bin/env python3
"""Recipe #90 doubled-float-arg launder sweep (task #177).

Per site `f(.., lbl_X, lbl_X, ..)` in a <100% fn: launder the SECOND
occurrence to `*(f32 *)&lbl_X`. Keep iff the containing fn's fuzzy improves
and nothing else regresses; revert otherwise.
"""
import json, os, re, subprocess, sys
sys.path.insert(0, 'tools')
import forward_decl_static_audit as FA
import extern_audit as EA

HEAT_MINUTES = 60
SKIP_FILES = set()
SKIP_SUBSTR = ['newclouds', 'loadCharacter', 'worldplanet',   # foxtrot-1
               'transporter', 'treasurechest',                # yankee-1
               'modgfx', 'dim_partfx']                        # xray-1
SITE_RE = re.compile(r'(\w+)\(([^;]{0,200}?)\b(lbl_\w+), (\3)\b')


def unit_name(p):
    return 'main/' + os.path.splitext(os.path.relpath(p, 'src'))[0]


def regen_report():
    if os.path.exists('build/GSAE01/report.json'):
        os.remove('build/GSAE01/report.json')
    return subprocess.run(['ninja', 'build/GSAE01/report.json'],
                          capture_output=True).returncode == 0


def unit_scores(unit):
    rep = json.load(open('build/GSAE01/report.json'))
    for u in rep['units']:
        if u['name'] == unit:
            return {f['name']: float(f.get('fuzzy_match_percent', 0.0))
                    for f in u.get('functions', [])}
    return None


def file_age_minutes(p):
    out = subprocess.run(['git', 'log', 'origin/main', '--pretty=%ct|%s',
                          '-5', '--', p], capture_output=True, text=True).stdout
    import time
    for line in out.splitlines():
        ct, _, subj = line.partition('|')
        if re.search(r'task #17[1378]', subj):
            continue
        return (time.time() - int(ct)) / 60
    return 10**9


def fn_at(text, pos):
    for start, end, stmt, kind in FA.top_level_statements(text):
        if kind == 'def' and start <= pos <= end:
            head = ' '.join(stmt.split('{', 1)[0].split())
            if '(' in head and not FA.PROTO_HEAD_SKIP.match(head):
                return EA.declarator_name(head.rstrip())
    return None


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    hits = json.load(open('/tmp/r90_sites.json'))
    files = sorted({h[0] for h in hits})
    kept, reverted, skipped = [], [], []
    for path in files:
        if only and only not in path:
            continue
        if path in SKIP_FILES or any(s in path for s in SKIP_SUBSTR):
            print(f'SKIP {path} (hot lane)')
            continue
        age = file_age_minutes(path)
        if age < HEAT_MINUTES:
            print(f'SKIP {path} (hot: {age:.0f} min)')
            continue
        unit = unit_name(path)
        opath = os.path.join('build/GSAE01', os.path.splitext(path)[0] + '.o')
        if not os.path.isfile(opath):
            continue
        base = unit_scores(unit)
        if base is None:
            continue
        progress = True
        tried = set()
        while progress:
            progress = False
            raw = open(path, encoding='utf-8', errors='replace').read()
            masked = FA.strip_comments_strings(raw)
            for m in SITE_RE.finditer(masked):
                key = (m.group(1), m.group(3), masked.count('\n', 0, m.start()))
                if key in tried:
                    continue
                tried.add(key)
                fn = fn_at(masked, m.start())
                if not fn:
                    continue
                sc = base.get(fn)
                if sc is None or sc >= 100.0 - 1e-6:
                    continue
                # launder the SECOND occurrence (group 4 span)
                s4, e4 = m.span(4)
                new = raw[:s4] + f'*(f32 *)&{m.group(3)}' + raw[e4:]
                open(path, 'w', encoding='utf-8').write(new)
                if subprocess.run(['ninja', opath], capture_output=True).returncode != 0 \
                        or not regen_report():
                    open(path, 'w', encoding='utf-8').write(raw)
                    subprocess.run(['ninja', opath], capture_output=True)
                    reverted.append((path, fn, m.group(1), 'build-fail'))
                    print(f'REVERT {path} {fn} {m.group(1)} (build-fail)')
                    continue
                now = unit_scores(unit)
                regressed = [n for n, s in now.items()
                             if n in base and s < base[n] - 1e-6]
                if not regressed and now.get(fn, 0) > sc + 1e-6:
                    kept.append((path, fn, m.group(1), sc, now[fn]))
                    print(f'KEEP {path} {fn} @{m.group(1)}: {sc:.2f}->{now[fn]:.2f}')
                    base = now
                    progress = True
                    break  # re-scan file (offsets changed)
                why = ('regressed ' + regressed[0]) if regressed else \
                      f'inert ({sc:.2f}->{now.get(fn,0):.2f})'
                open(path, 'w', encoding='utf-8').write(raw)
                subprocess.run(['ninja', opath], capture_output=True)
                reverted.append((path, fn, m.group(1), why))
                print(f'revert {path} {fn} @{m.group(1)} ({why})')
        regen_report()
    print(f'\nkept: {len(kept)}, reverted/inert: {len(reverted)}')
    json.dump({'kept': kept, 'reverted': reverted},
              open('/tmp/r90_results.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
