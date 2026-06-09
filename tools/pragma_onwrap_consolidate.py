#!/usr/bin/env python3
"""Phase 2 consolidator (task #23): flip a majority-off MIXED TU to default-off
cflags and preserve the minority on-functions with minimal per-function on-wraps.

For each unit: set cflags=cflags_dll_noopt (default off), strip ALL scheduling/
peephole off+reset pragmas, and for each wants_on function defined in the .c add
`#pragma <pass> on`...`reset` ONLY for the pass(es) the function currently runs
ON (computed from the original pragma-stack effective state, recipe #1). Result
is byte-neutral by construction; gated per-unit .o byte-identical (units whose
on-function is a header-inline -- no .c def to wrap -- fail the gate and revert).

Usage: python3 tools/pragma_onwrap_consolidate.py --units F.json [--start N --count M]
       (F.json: list of "src/.../unit.c"; needs /tmp/pragma_pertu.json for wants_on)
"""
import argparse, hashlib, json, os, re, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGURE = os.path.join(ROOT, 'configure.py')
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import pragma_inert_audit as pia
import pragma_scoped_flip as psf

PRAG = re.compile(r'^\s*#pragma\s+(scheduling|peephole)\s+(off|on|reset)\s*$')

def sh(p):
    return hashlib.sha1(open(p,'rb').read()).hexdigest() if os.path.exists(p) else None

def effective_states(lines):
    """Return list of (sched,peep) effective state per line index (True=on)."""
    sched=['on']; peep=['on']  # default-on stacks (cflags_base)
    out=[]
    for ln in lines:
        m=PRAG.match(ln.decode('latin1'))
        out.append((sched[-1]=='on', peep[-1]=='on'))
        if m:
            kind,state=m.group(1),m.group(2)
            st = sched if kind=='scheduling' else peep
            if state=='off': st.append('off')
            elif state=='on': st.append('on')
            elif state=='reset':
                if len(st)>1: st.pop()
    return out

def find_def_span(lines, name):
    """Find (start_idx, end_idx) of the definition of `name` (col-0 type, then braces)."""
    sig=re.compile(r'^[A-Za-z_][\w \t\*]*\b'+re.escape(name)+r'\s*\(')
    for i,ln in enumerate(lines):
        s=ln.decode('latin1')
        if sig.match(s) and not s.lstrip().startswith(('return','//','*')):
            depth=0; started=False
            for j in range(i, min(i+400,len(lines))):
                t=lines[j].decode('latin1')
                depth += t.count('{') - t.count('}')
                if '{' in t: started=True
                if started and depth<=0:
                    return (i, j)
            return None
    return None

def transform(path, wants_on):
    raw=open(path,'rb').read()
    lines=raw.split(b'\n')
    eff=effective_states(lines)
    wraps={}  # start_idx -> (end_idx, passes_needed_on)
    for name in wants_on:
        span=find_def_span(lines,name)
        if span is None:
            return None, f'def-not-found:{name}'
        si,ei=span
        sched_on,peep_on=eff[si]
        passes=[p for p,on in (('scheduling',sched_on),('peephole',peep_on)) if on]
        if passes:
            wraps[si]=(ei,passes)
    out=[]
    closes={}
    for i,ln in enumerate(lines):
        if i in wraps:
            ei,passes=wraps[i]
            for p in passes: out.append(('#pragma %s on'%p).encode())
            closes.setdefault(ei,[]).extend(reversed(passes))
        if PRAG.match(ln.decode('latin1')):
            pass
        else:
            out.append(ln)
        if i in closes:
            for p in closes[i]: out.append(('#pragma %s reset'%p).encode())
    return b'\n'.join(out), None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--units',required=True)
    ap.add_argument('--start',type=int,default=0)
    ap.add_argument('--count',type=int,default=10)
    ap.add_argument('--pertu',default='/tmp/pragma_pertu.json')
    args=ap.parse_args()
    psf.CFLAG_VAR='cflags_dll_noopt'; psf.CFLAG_MODE='replace'
    allu=json.load(open(args.units))[args.start:args.start+args.count]
    pertu=json.load(open(args.pertu))
    tus=pia.discover_tus()
    cfg0=open(CONFIGURE).read()
    objs={u:tus[u] for u in allu if u in tus}
    subprocess.run(['ninja']+list(objs.values()),cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    snap={u:sh(os.path.join(ROOT,objs[u])) for u in objs}
    c0={u:open(os.path.join(ROOT,u),'rb').read() for u in objs}
    cfg=cfg0; applied=[]; errs={}
    for u in objs:
        won=[s for s in pertu[u]['wants_on']]
        new,err=transform(os.path.join(ROOT,u),won)
        if err: errs[u]=err; continue
        open(os.path.join(ROOT,u),'wb').write(new)
        cfg,ok=psf.add_extra_cflags(cfg,psf.conf_path(u))
        if not ok: errs[u]='cfg-miss'; open(os.path.join(ROOT,u),'wb').write(c0[u]); continue
        applied.append(u)
    open(CONFIGURE,'w').write(cfg)
    subprocess.run([sys.executable,'configure.py'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['ninja']+[objs[u] for u in applied],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    failed=[u for u in applied if sh(os.path.join(ROOT,objs[u]))!=snap[u]]
    ok_units=[u for u in applied if u not in failed]
    cfg=cfg0
    for u in ok_units: cfg,_=psf.add_extra_cflags(cfg,psf.conf_path(u))
    open(CONFIGURE,'w').write(cfg)
    for u in failed: open(os.path.join(ROOT,u),'wb').write(c0[u])
    subprocess.run([sys.executable,'configure.py'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['ninja']+[objs[u] for u in objs],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    bad=[u for u in ok_units if sh(os.path.join(ROOT,objs[u]))!=snap[u]]
    print(f'SUCCEEDED (byte-identical): {len(ok_units)}')
    for u in ok_units: print('  OK  ',u)
    print(f'FAILED .o gate (reverted): {len(failed)}')
    for u in failed: print('  GATE',u)
    print(f'def-not-found / errors: {len(errs)}')
    for u,e in errs.items(): print('  ERR ',u,e)
    if bad: print('  WARNING not-restored:',bad)
    json.dump({'ok':ok_units,'failed':failed,'errs':errs},open('/tmp/onwrap_last.json','w'))
    return 1 if bad else 0

if __name__=='__main__':
    sys.exit(main())
