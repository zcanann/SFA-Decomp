import re,sys,subprocess,difflib
unit,sym=sys.argv[1],sys.argv[2]
txt=subprocess.run(['python3','tools/function_objdump.py',unit,sym],capture_output=True,text=True).stdout
tgt,cur=txt.split('===== current')
def insns(s,blind):
    out=[]
    for l in s.split('\n'):
        m=re.match(r'\s+[0-9a-f]+:\t(?:[0-9a-f]{2} ){4}\t(.*)',l)
        if m:
            t=re.sub(r'<.*','',m.group(1)).strip()
            t=re.sub(r'\b(0x)?[0-9a-f]{4,}\b','A',t)
            if blind: t=re.sub(r'\br\d+\b','R',t); t=re.sub(r'\bf\d+\b','F',t)
            out.append(t)
        elif 'R_PPC' in l:
            out.append('RELOC '+l.split()[-1])
    return out
for blind in (False,True):
    T=insns(tgt,blind); C=insns(cur,blind)
    sm=difflib.SequenceMatcher(a=T,b=C,autojunk=False)
    n=0; regions=[]
    for tag,i1,i2,j1,j2 in sm.get_opcodes():
        if tag=='equal': continue
        n+=max(i2-i1,j2-j1); regions.append((tag,T[i1:i2],C[j1:j2]))
    print(('REGBLIND' if blind else 'RAW'),'target',len(T),'cur',len(C),'diff',n)
    if blind:
        for tag,a,b in regions: print(' ',tag,'T:',a,'\n      C:',b)
