#!/usr/bin/env python3
"""Differential probe for MWCC GC/2.0 callee-saved register assignment.

Compiles synthetic C functions with the project's real mwcceppc and reads back
which saved register each source-level value received, using store+SDA21-reloc
pairs against distinct extern sinks as the variable->register oracle.

Needs no debugger and no reverse engineering: it measures the shipped compiler
directly. See docs/mwcc_re/REGISTER_ORDER_EMPIRICAL_RULE.md for the derived rule.

Usage:
    python3 tools/mwcc_re/regorder_probe.py              # run the built-in case library
    python3 tools/mwcc_re/regorder_probe.py --case NAME  # one case, with disassembly
    python3 tools/mwcc_re/regorder_probe.py --file X.c   # your own probe file

A probe function stores each value it wants measured to a distinct extern named
`out<KEY>`; the tool reports `<KEY>=<reg>`. Values must be live across a call
(use the `barrier()` extern) to be given a callee-saved register at all.
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MWCC = os.path.join(ROOT, "build/compilers/GC/2.0/mwcceppc.exe")
WIBO = os.path.join(ROOT, "build/tools/wibo")
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")

CFLAGS = ("-nodefaults -proc gekko -align powerpc -enum int -fp hardware "
          "-Cpp_exceptions off -O4,p -inline auto -maxerrors 1 -nosyspath "
          "-RTTI off -fp_contract on -str reuse -multibyte -DNDEBUG=1 -W off").split()

STORE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(stw|stfs|stfd|sth|stb)\s+(r\d+|f\d+),")
RELOC = re.compile(r"R_PPC_EMB_SDA21\s+(\S+)")


def compile_and_dump(src_path, obj_path, extra=()):
    if os.path.exists(obj_path):
        os.remove(obj_path)
    r = subprocess.run([WIBO, MWCC] + CFLAGS + list(extra) + ["-c", src_path, "-o", obj_path],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(obj_path):
        return None, (r.stdout + r.stderr).strip()
    d = subprocess.run([OBJDUMP, "-M", "gekko", "-drz", obj_path],
                       cwd=ROOT, capture_output=True, text=True)
    return d.stdout, None


def var_regs(dis):
    """Map sink-global name -> register via store instruction + its SDA21 reloc."""
    out = {}
    lines = dis.splitlines()
    for i, ln in enumerate(lines):
        s = STORE.match(ln)
        if s and i + 1 < len(lines):
            rl = RELOC.search(lines[i + 1])
            if rl:
                out.setdefault(rl.group(1), s.group(2))
    return out


HDR = """
typedef unsigned char u8; typedef short s16;
typedef struct Obj { int id; int x; struct Obj* next; } Obj;
extern Obj* getobj(void);
extern int f0(void); extern int f1(void); extern int f2(void);
extern int f3(void); extern int f4(void); extern int f5(void);
extern int g(int);
extern void barrier(void);
extern void use(int);
extern void take(int*);
extern int cond;
extern int outa, outb, outc, outd, oute, outf;
"""

CASES = {
    # --- decl order vs first-def order -------------------------------------
    "decl_eq_def": "void probe(void){ int a=f0(); int b=f1(); int c=f2();"
                   " barrier(); outa=a; outb=b; outc=c; }",
    "decl_rev_def_fwd": "void probe(void){ int c; int b; int a;"
                        " a=f0(); b=f1(); c=f2(); barrier(); outa=a; outb=b; outc=c; }",
    "decl_fwd_def_rev": "void probe(void){ int a; int b; int c;"
                        " c=f0(); b=f1(); a=f2(); barrier(); outa=a; outb=b; outc=c; }",
    "use_order_rev": "void probe(void){ int a=f0(); int b=f1(); int c=f2();"
                     " barrier(); outc=c; outb=b; outa=a; }",
    "six_locals": "void probe(void){ int a=f0(); int b=f1(); int c=f2(); int d=f3();"
                  " int e=f4(); int ff=f5(); barrier();"
                  " outa=a; outb=b; outc=c; outd=d; oute=e; outf=ff; }",
    # --- params -------------------------------------------------------------
    "three_params": "void probe(int p,int q,int r){ barrier(); outa=p; outb=q; outc=r; }",
    "params_and_locals": "void probe(int p,int q){ int a=f0(); int b=f1(); barrier();"
                         " outa=a; outb=b; outc=p; outd=q; }",
    "param_reassigned": "void probe(int p){ int a=f0(); int b=f1(); p=g(p); barrier();"
                        " outa=a; outb=b; outc=p; }",
    # --- temps that displace the ordinary band ------------------------------
    "loop_accumulator": "void probe(void){ int a=f0(); int b=f1(); int c=0; int i;"
                        " for(i=0;i<4;i++) c+=g(i); barrier(); outa=a; outb=b; outc=c; }",
    "nested_loops": "void probe(void){ int a=f0(); int L=0; int M=0; int i,j;"
                    " for(i=0;i<4;i++){ L+=g(i); for(j=0;j<3;j++) M+=g(j); }"
                    " barrier(); outa=a; outb=L; outc=M; }",
    "phi_if": "void probe(void){ int a=f0(); int b=0; int c=f2(); if(cond) b=f1();"
              " barrier(); outa=a; outb=b; outc=c; }",
    "phi_switch": "void probe(void){ int a=f0(); int b=0; int c=f2();"
                  " switch(cond){case 1: b=f1(); break; case 2: b=f3(); break;}"
                  " barrier(); outa=a; outb=b; outc=c; }",
    "narrow_s16": "void probe(void){ u8 a=(u8)f0(); s16 b=(s16)f1(); int c=f2();"
                  " barrier(); outa=a; outb=b; outc=c; }",
    # --- eligibility --------------------------------------------------------
    "addr_taken": "void probe(void){ int a=f0(); int b=f1(); int c=f2(); take(&b);"
                  " barrier(); outa=a; outb=b; outc=c; }",
    "dead_local": "void probe(void){ int a=f0(); int z; int b=f1(); int c=f2();"
                  " barrier(); outa=a; outb=b; outc=c; }",
    "pure_alias": "void probe(int p){ int sz=p; int a=f0(); int b=f1(); barrier();"
                  " outa=a; outb=b; outc=sz; outd=p; }",
    "cast_alias": "void probe(Obj* o){ int oid=(int)o; int a=f0(); int b=f1(); barrier();"
                  " outa=a; outb=b; outc=oid; }",
    # --- classes ------------------------------------------------------------
    "floats": "extern float ff0(void),ff1(void),ff2(void); extern float fa,fb,fc;"
              " void probe(void){ float a=ff0(); float b=ff1(); float c=ff2();"
              " barrier(); fa=a; fb=b; fc=c; }",
    "floats_def_rev": "extern float ff0(void),ff1(void),ff2(void); extern float fa,fb,fc;"
                      " void probe(void){ float a,b,c; c=ff0(); b=ff1(); a=ff2();"
                      " barrier(); fa=a; fb=b; fc=c; }",
    "mixed_classes": "extern float ff0(void),ff1(void); extern float fc,fd;"
                     " void probe(void){ int a=f0(); float c=ff0(); int b=f1();"
                     " float d=ff1(); barrier(); outa=a; outb=b; fc=c; fd=d; }",
}

SINKS = ["a", "b", "c", "d", "e", "f"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case")
    ap.add_argument("--file")
    ap.add_argument("--workdir", default="/tmp/mwcc_regorder")
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)

    if a.file:
        dis, err = compile_and_dump(a.file, os.path.join(a.workdir, "user.o"))
        if err:
            print("ERROR:", err)
            return 1
        print(dis)
        print("map:", var_regs(dis))
        return 0

    names = [a.case] if a.case else list(CASES)
    for n in names:
        if n not in CASES:
            print(f"no such case: {n}")
            return 1
        cf = os.path.join(a.workdir, n + ".c")
        with open(cf, "w") as f:
            f.write(HDR + "\n" + CASES[n] + "\n")
        dis, err = compile_and_dump(cf, os.path.join(a.workdir, n + ".o"))
        if err:
            print(f"{n:<22} ERROR {err[:100]}")
            continue
        m = var_regs(dis)
        cols = []
        for k in SINKS:
            for pfx in ("out", "f"):
                if pfx + k in m:
                    cols.append(f"{k}={m[pfx + k]}")
                    break
        print(f"{n:<22} " + "  ".join(cols))
        if a.case:
            print(dis)
    return 0


if __name__ == "__main__":
    sys.exit(main())
