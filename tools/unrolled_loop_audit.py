#!/usr/bin/env python3
"""unrolled_loop_audit.py -- find fns where TARGET has more `slw` than current.

The #28 manual-unroll signature: the import hand-wrote a manual loop unroll
(folding 1<<i / 2<<i to constants) where the original was a `for` loop that
MWCC unrolls keeping the runtime `slw` form. Target shows MORE slw instructions
than current => rewrite the manual unroll as a for-loop to recover them.
(sky skyFn_80088c94 69.8->99.2 precedent.)

CRITICAL: re-run after a FULL build -- stale .o gives false positives.
Promoted from miner-3's /tmp/sweep28.py (task #20/#21, 2026-06-08).
"""
import json,subprocess,os,re
d=json.load(open('build/GSAE01/report.json'))
# map report unit -> source .o path
# report unit name like 'main/main/sky' ; config has source_path
cfg=json.load(open('build/GSAE01/config.json'))
# build name->object paths from config
units={}
for u in cfg['units']:
    name=u['name']  # e.g. main/newshadows.c
    units[name]=u
# report units carry metadata.source_path? use report unit 'name' diff. Let's map via report
def objdump_slw(path):
    # returns {sym: slw_count}
    try:
        out=subprocess.run(['build/binutils/powerpc-eabi-objdump','-d',path],capture_output=True,text=True,timeout=60).stdout
    except Exception:
        return {}
    res={}
    cur=None
    for line in out.splitlines():
        m=re.match(r'[0-9a-f]+ <([^>]+)>:',line)
        if m: cur=m.group(1); res[cur]=0; continue
        if cur:
            parts=line.split('\t')
            if len(parts)>=3 and parts[2].strip().split()[0:1]==['slw']: res[cur]+=1
    return res
# iterate report units, find target .o and src .o
cands=[]
for u in d['units']:
    rn=u['name']  # main/main/sky
    parts=[f for f in u.get('functions',[]) if f.get('fuzzy_match_percent',100)<100]
    if not parts: continue
    # find source_path from metadata
    sp=u.get('metadata',{}).get('source_path')
    if not sp: continue
    rel=sp[4:] if sp.startswith('src/') else sp
    tgt='build/GSAE01/obj/'+rel[:-2]+'.o' if rel.endswith('.c') else None
    src='build/GSAE01/src/'+rel[:-2]+'.o' if rel.endswith('.c') else None
    if not (tgt and os.path.exists(tgt) and os.path.exists(src)): continue
    ts=objdump_slw(tgt); cs=objdump_slw(src)
    for f in parts:
        n=f['name']
        if ts.get(n,0)>cs.get(n,0):
            cands.append((f.get('fuzzy_match_percent',100),ts.get(n,0),cs.get(n,0),rn,n))
cands.sort()
for pct,t,c,rn,n in cands:
    print('%5.1f  Tslw=%d Cslw=%d  %s  %s'%(pct,t,c,rn,n))
print('TOTAL',len(cands))
