#!/usr/bin/env python3
"""callset_audit.py -- find call-set divergences between target and current .o.

The CALL-SET-DIFF field (task #21): a sub-100 fn whose set of `bl` targets
differs from target's reveals one of two recoverable import bugs:

  (1) AUTO-INLINE VICTIM -- a callee appears as `bl` in TARGET but is missing
      from CURRENT (the caller inlined a same-TU helper that target keeps as a
      call). Fix: wrap the callee definition in `#pragma dont_inline on` ...
      `reset`. CAUTION (CLAUDE.md): only when the wrapped fn has no callees IT
      needs inlined -- else place the caller BEFORE the callee def (source-order
      fix) so MWCC can't inline it upward. Full .o-hash A/B mandatory.

  (2) WRONG-SYMBOL EXTERN -- CURRENT calls a phantom address-named extern
      (FUN_xxxx / fn_xxxx) where TARGET calls a canonical symbol. Fix: use the
      canonical name; VERIFY the address maps via config/GSAE01/symbols.txt.

Output: sub-100 fns ranked by fuzzy%, with TGT-only and CUR-only bl targets.
savegpr/restgpr-only differences are filtered (not real call-set bugs).

CRITICAL: re-run after a FULL build -- stale .o files give false positives
(e.g. isSpace). report.json must be current.

Reusable instrument (cf. pragma_audit.py, fcmpo_swap_audit.py,
rotation_decl_audit.py, cosmetic_audit.py). Promoted from miner-3's
/tmp/callsweep.py (task #21, 2026-06-08).
"""
import json,subprocess,os,re
from collections import Counter
d=json.load(open('build/GSAE01/report.json'))
OBJ='build/binutils/powerpc-eabi-objdump'
def calls(path):
    try: out=subprocess.run([OBJ,'-dr',path],capture_output=True,text=True,timeout=90).stdout
    except: return {}
    res={};cur=None
    for line in out.splitlines():
        m=re.match(r'[0-9a-f]+ <([^>]+)>:',line)
        if m: cur=m.group(1); res[cur]=[]; continue
        if cur and 'R_PPC_REL24' in line:
            t=line.split('R_PPC_REL24')[1].strip().split()[0]
            res[cur].append(t)
    return res
out=[]
for u in d['units']:
    sp=u.get('metadata',{}).get('source_path')
    parts=[f for f in u.get('functions',[]) if f.get('fuzzy_match_percent',100)<100]
    if not sp or not parts: continue
    rel=sp[4:] if sp.startswith('src/') else sp
    if not rel.endswith('.c'): continue
    tgt='build/GSAE01/obj/'+rel[:-2]+'.o'; src='build/GSAE01/src/'+rel[:-2]+'.o'
    if not(os.path.exists(tgt) and os.path.exists(src)): continue
    tc=calls(tgt); cc=calls(src)
    for f in parts:
        n=f['name']
        def norm(lst): return Counter(re.sub(r'\+0x[0-9a-f]+','',x) for x in lst)
        ta=norm(tc.get(n,[])); ca=norm(cc.get(n,[]))
        if ta!=ca:
            only_t=ta-ca; only_c=ca-ta
            keys=set(only_t)|set(only_c)
            if all('savegpr' in k or 'restgpr' in k for k in keys): continue
            out.append((f.get('fuzzy_match_percent',100),u['name'],n,dict(only_t),dict(only_c)))
out.sort()
for pct,un,n,ot,oc in out:
    print('%5.1f %s %s'%(pct,un,n))
    if ot: print('     TGT-only:',ot)
    if oc: print('     CUR-only:',oc)
print('TOTAL',len(out))
