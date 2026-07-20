#!/usr/bin/env python3
"""Screen for un-modelled incoming parameters.

A register the target function NEVER WRITES but DOES read is an incoming value,
i.e. a parameter. If our source signature does not declare it, the parameter is
un-modelled and codegen cannot match.

Reports, per function, the argument-ABI registers (r3-r10, f1-f13) that are read
but never defined anywhere in the retail body.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")

# instructions whose FIRST operand is a source, not a destination
SRC_FIRST = re.compile(
    r"^(st|b|cmp|cr|mt|tw|dcb|icb|sync|isync|eieio|nop|psq_st|fcmp)"
)
REG = re.compile(r"\b([rf])(\d+)\b")


def disasm(obj, symbol):
    out = subprocess.run(
        [OBJDUMP, "-M", "gekko", "-drz", obj], capture_output=True, text=True
    ).stdout
    lines, on = [], False
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:$", line.strip())
        if m:
            on = m.group(1) == symbol
            continue
        if on and re.match(r"^\s+[0-9a-f]+:\s", line):
            lines.append(line)
    return lines


def analyze(lines):
    """Strict, control-flow-independent def/use.

    `defined` is every register written ANYWHERE in the body, so a register
    defined on a loop back edge is never mistaken for an incoming value.
    """
    defined, used = set(), []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].split():
            continue
        mnem = parts[2].split()[0]
        ops = parts[2][len(mnem):].strip()
        ops = ops.split("#")[0]
        # a branch operand is a target ADDRESS, not a register: "b f10 <sym>"
        # would otherwise read as fpr f10
        ops = ops.split("<")[0]
        if mnem.startswith("b") and mnem not in ("bctrl", "blrl"):
            continue
        regs = [(k + n) for k, n in REG.findall(ops)]
        if not regs:
            continue
        srcs, dst = regs, None
        if not SRC_FIRST.match(mnem):
            dst, srcs = regs[0], regs[1:]
        used.extend(srcs)
        if dst:
            defined.add(dst)
        if mnem in ("blrl", "bctrl"):
            for i in range(3, 13):
                defined.add("r%d" % i)
            for i in range(1, 14):
                defined.add("f%d" % i)
    return defined, used


ARGS = {"r%d" % i for i in range(3, 11)} | {"f%d" % i for i in range(1, 14)}


def check(obj, symbol):
    lines = disasm(obj, symbol)
    if not lines:
        return None
    defined, used = analyze(lines)
    incoming = {r for r in used if r in ARGS and r not in defined}
    return sorted(incoming, key=lambda r: (r[0], int(r[1:])))


def main():
    obj, sym = sys.argv[1], sys.argv[2]
    print(check(obj, sym))


if __name__ == "__main__":
    main()
